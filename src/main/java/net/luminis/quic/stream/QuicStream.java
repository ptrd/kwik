/*
 * Copyright © 2019, 2020 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package net.luminis.quic.stream;

import net.luminis.quic.QuicConnectionImpl;
import net.luminis.quic.Version;
import net.luminis.quic.frame.MaxStreamDataFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.NullLogger;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Consumer;


public class QuicStream extends BaseStream {

    protected static long waitForNextFrameTimeout = Long.MAX_VALUE;
    protected static final float receiverMaxDataIncrementFactor = 0.10f;

    private Object addMonitor = new Object();
    protected final Version quicVersion;
    protected final int streamId;
    protected final QuicConnectionImpl connection;
    protected final FlowControl flowController;
    protected final Logger log;
    private StreamInputStream inputStream;
    private StreamOutputStream outputStream;
    private volatile boolean aborted;
    private volatile Thread blocking;
    private long receiverFlowControlLimit;
    private long lastCommunicatedMaxData;
    private final long receiverMaxDataIncrement;
    private volatile int lastOffset = -1;


    public QuicStream(int streamId, QuicConnectionImpl connection, FlowControl flowController) {
        this(Version.getDefault(), streamId, connection, flowController, new NullLogger());
    }

    public QuicStream(int streamId, QuicConnectionImpl connection, FlowControl flowController, Logger log) {
        this(Version.getDefault(), streamId, connection, flowController, log);
    }

    public QuicStream(Version quicVersion, int streamId, QuicConnectionImpl connection, FlowControl flowController, Logger log) {
        this.quicVersion = quicVersion;
        this.streamId = streamId;
        this.connection = connection;
        this.flowController = flowController;
        this.log = log;
        inputStream = new StreamInputStream();
        outputStream = new StreamOutputStream();

        receiverFlowControlLimit = connection.getInitialMaxStreamData();
        lastCommunicatedMaxData = receiverFlowControlLimit;
        receiverMaxDataIncrement = (long) (receiverFlowControlLimit * receiverMaxDataIncrementFactor);
    }

    public InputStream getInputStream() {
        return inputStream;
    }

    public OutputStream getOutputStream() {
        return outputStream;
    }

    /**
     * Adds a newly received frame to the stream.
     *
     * This method is intentionally package-protected, as it should only be called by the (Stream)Packet processor.
     * @param frame
     */
    void add(StreamFrame frame) {
        synchronized (addMonitor) {
            super.add(frame);
            if (frame.isFinal()) {
                lastOffset = frame.getUpToOffset();
            }
            addMonitor.notifyAll();
        }
    }

    @Override
    protected boolean isStreamEnd(int offset) {
        return lastOffset >= 0 && offset >= lastOffset;
    }

    public int getStreamId() {
        return streamId;
    }

    public boolean isUnidirectional() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-2.1
        // "The second least significant bit (0x2) of the stream ID distinguishes
        //   between bidirectional streams (with the bit set to 0) and
        //   unidirectional streams (with the bit set to 1)."
        return (streamId & 0x0002) == 0x0002;
    }

    public boolean isClientInitiatedBidirectional() {
        // "Client-initiated streams have even-numbered stream IDs (with the bit set to 0)"
        return (streamId & 0x0003) == 0x0000;
    }

    public boolean isServerInitiatedBidirectional() {
        // "server-initiated streams have odd-numbered stream IDs"
        return (streamId & 0x0003) == 0x0001;
    }

    @Override
    public String toString() {
        return "Stream " + streamId;
    }

    private class StreamInputStream extends InputStream {

        @Override
        public int available() throws IOException {
            return Integer.max(0, QuicStream.this.bytesAvailable());
        }

        // InputStream.read() contract:
        // - The value byte is returned as an int in the range 0 to 255.
        // - If no byte is available because the end of the stream has been reached, the value -1 is returned.
        // - This method blocks until input data is available, the end of the stream is detected, or an exception is thrown.
        @Override
        public int read() throws IOException {
            byte[] data = new byte[1];
            int bytesRead = read(data, 0, 1);
            if (bytesRead == 1) {
                return data[0] & 0xff;
            }
            else if (bytesRead < 0) {
                // End of stream
                return -1;
            }
            else {
                // Impossible
                throw new RuntimeException();
            }
        }

        // InputStream.read() contract:
        // - An attempt is made to read the requested number of bytes, but a smaller number may be read.
        // - This method blocks until input data is available, end of file is detected, or an exception is thrown.
        // - If requested number of bytes is greater than zero, an attempt is done to read at least one byte.
        // - If no byte is available because the stream is at end of file, the value -1 is returned;
        //   otherwise, at least one byte is read and stored into the given byte array.
        @Override
        public int read(byte[] buffer, int offset, int len) throws IOException {
            Instant readAttemptStarted = Instant.now();
            long waitPeriod = waitForNextFrameTimeout;
            while (true) {
                if (aborted) {
                    throw new ProtocolException("Connection aborted");
                }

                synchronized (addMonitor) {
                    try {
                        blocking = Thread.currentThread();

                        int bytesRead = QuicStream.this.read(ByteBuffer.wrap(buffer, offset, len));
                        if (bytesRead > 0) {
                            updateAllowedFlowControl(bytesRead);
                            return bytesRead;
                        } else if (bytesRead < 0) {
                            // End of stream
                            return -1;
                        }

                        // Nothing read: block until bytes can be read, read timeout or abort
                        try {
                            addMonitor.wait(waitPeriod);
                        } catch (InterruptedException e) {
                            if (aborted) {
                                throw new ProtocolException("Connection aborted");
                            }
                        }
                    }
                    finally {
                         blocking = null;
                    }
                }

                if (bytesAvailable() <= 0) {
                    long waited = Duration.between(readAttemptStarted, Instant.now()).toMillis();
                    if (waited > waitForNextFrameTimeout) {
                        throw new SocketTimeoutException("Read timeout on stream " + streamId + "; read up to " + readOffset());
                    } else {
                        waitPeriod = Long.max(1, waitForNextFrameTimeout - waited);
                    }
                }
            }
        }

        private void updateAllowedFlowControl(int bytesRead) {
            // Slide flow control window forward (which as much bytes as are read)
            receiverFlowControlLimit += bytesRead;
            connection.updateConnectionFlowControl(bytesRead);
            // Avoid sending flow control updates with every single read; check diff with last send max data
            if (receiverFlowControlLimit - lastCommunicatedMaxData > receiverMaxDataIncrement) {
                connection.send(new MaxStreamDataFrame(streamId, receiverFlowControlLimit), this::retransmitMaxData);
                lastCommunicatedMaxData = receiverFlowControlLimit;
            }
        }

        private void retransmitMaxData(QuicFrame lostFrame) {
            connection.send(new MaxStreamDataFrame(streamId, receiverFlowControlLimit), this::retransmitMaxData);
            log.recovery("Retransmitted max stream data, because lost frame " + lostFrame);
        }
    }

    private class StreamOutputStream extends OutputStream {
        int currentOffset;

        @Override
        public void write(byte[] data) throws IOException {
            write(data, 0, data.length);
        }

        @Override
        public void write(byte[] data, int off, int len) throws IOException {
            long flowControlLimit = flowController.increaseFlowControlLimit(QuicStream.this, currentOffset + len);
            if (currentOffset + len <= flowControlLimit) {
                sendData(data, off, len);
            }
            else {
                int sizeOfFirstWrite = (int) (flowControlLimit - currentOffset);
                sendData(data, off, sizeOfFirstWrite);

                try {
                    flowController.waitForFlowControlCredits(QuicStream.this);
                } catch (InterruptedException e) {
                    throw new InterruptedIOException();
                }

                write(data, off + sizeOfFirstWrite, len - sizeOfFirstWrite);    // TODO: refactor recursion to while
            }
        }

        @Override
        public void write(int dataByte) throws IOException {
            write(new byte[] { (byte) dataByte }, 0, 1);
        }

        @Override
        public void flush() throws IOException {
            // No-op, this implementation flushes immediately.
        }

        @Override
        public void close() throws IOException {
            send(new StreamFrame(quicVersion, streamId, currentOffset, new byte[0], true), this::retransmitStreamFrame, true);
        }

        private void sendData(byte[] data, int off, int len) {
            int maxDataPerFrame = connection.getMaxPacketSize() - StreamFrame.maxOverhead() - connection.getMaxShortHeaderPacketOverhead();
            int remaining = len;
            int offsetInDataArray = off;
            while (remaining > 0) {
                int bytesInFrame = Math.min(maxDataPerFrame, remaining);
                StreamFrame frame = new StreamFrame(quicVersion, streamId, currentOffset, data, offsetInDataArray, bytesInFrame, false);
                send(frame, this::retransmitStreamFrame, false);
                remaining -= bytesInFrame;
                offsetInDataArray += bytesInFrame;
                currentOffset += bytesInFrame;
            }
        }

        private void retransmitStreamFrame(QuicFrame frame) {
            connection.send(frame, this::retransmitStreamFrame, true);
            log.recovery("Retransmitted lost stream frame " + frame);
        }
    }

    protected void resetOutputStream() {
        outputStream.currentOffset = 0;
    }

    protected void send(StreamFrame frame, Consumer<QuicFrame> lostFrameCallback, boolean flush) {
        connection.send(frame, lostFrameCallback, flush);
    }

    void abort() {
        aborted = true;
        if (blocking != null) {
            blocking.interrupt();
        }
    }

}
