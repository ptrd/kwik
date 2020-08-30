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
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;


public class QuicStream {

    protected static long waitForNextFrameTimeout = Long.MAX_VALUE;
    protected static final float receiverMaxDataIncrementFactor = 0.10f;

    private Object addMonitor = new Object();
    protected final Version quicVersion;
    protected final int streamId;
    protected final QuicConnectionImpl connection;
    protected final FlowControl flowController;
    protected final Logger log;
    private final BlockingQueue<StreamFrame> queuedFrames;
    private StreamFrame currentFrame;
    private int currentOffset;
    private int expectingOffset;
    private Map<Integer, StreamFrame> receivedFrames;
    private StreamInputStream inputStream;
    private StreamOutputStream outputStream;
    private volatile boolean aborted;
    private volatile Thread blocking;
    private long receiverMaxData;
    private long lastCommunicatedMaxData;
    private final long receiverMaxDataIncrement;


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
        queuedFrames = new LinkedBlockingQueue<>();  // Queued frames are the ones eligible for reading, because they are contiguous
        receivedFrames = new ConcurrentHashMap<>();  // Received frames are the ones not (yet) eligible for reading, because they are non-contiguous
        inputStream = new StreamInputStream();
        outputStream = new StreamOutputStream();

        receiverMaxData = connection.getInitialMaxStreamData();
        lastCommunicatedMaxData = receiverMaxData;
        receiverMaxDataIncrement = (long) (receiverMaxData * receiverMaxDataIncrementFactor);
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
        String logMessage = null;

        synchronized (addMonitor) {
            if (frame.getOffset() == expectingOffset) {
                queuedFrames.add(frame);
                expectingOffset += frame.getLength();
                while (receivedFrames.containsKey(expectingOffset)) {
                    // Next frame was already received; move it to the incoming queue
                    StreamFrame nextFrame = receivedFrames.remove(expectingOffset);
                    queuedFrames.add(nextFrame);
                    expectingOffset += nextFrame.getLength();
                }
            }
            else {
                // Store frame for later use
                if (! receivedFrames.containsKey(frame.getOffset())) {
                    receivedFrames.put(frame.getOffset(), frame);
                }
                else {
                    logMessage = "Received duplicate frame " + frame;
                }
            }
        }
        if (logMessage != null) {
            log.debug(logMessage);
        }
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
            if (currentFrame == null || !(currentOffset < currentFrame.getOffset() + currentFrame.getLength()) && !currentFrame.isFinal()) {
                currentFrame = queuedFrames.poll();  // Does not block
            }
            if (currentFrame != null) {
                return currentFrame.getOffset() + currentFrame.getLength() - currentOffset;
            }
            else {
                return 0;
            }
        }

        @Override
        public int read() throws IOException {
            if (aborted)
                throw new ProtocolException("Connection aborted");

            blocking = Thread.currentThread();  // TODO: this works for one blocking reader thread only
            if (currentFrame == null) {
                try {
                    // Because the read method is supposed to block, the timeout should be (nearly) infinite.
                    currentFrame = queuedFrames.poll(waitForNextFrameTimeout, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    if (aborted) {
                        blocking = null;
                        throw new ProtocolException("Connection aborted");
                    }
                    /* Nothing to do, currentFrame will stay null. */ }
                if (currentFrame == null) {
                    blocking = null;
                    throw new SocketTimeoutException();
                }
            }
            blocking = null;
            if (currentOffset < currentFrame.getOffset() + currentFrame.getLength()) {
                byte data = currentFrame.getStreamData()[currentOffset - currentFrame.getOffset()];
                currentOffset++;
                // Flow control
                receiverMaxData += 1;  // Slide flow control window forward (which as much bytes as are read)
                connection.slideFlowControlWindow(1);
                if (receiverMaxData - lastCommunicatedMaxData > receiverMaxDataIncrement) {
                    // Avoid sending updates which every single byte read...
                    connection.send(new MaxStreamDataFrame(streamId, receiverMaxData), this::retransmitMaxData);
                    lastCommunicatedMaxData = receiverMaxData;
                }

                return data & 0xff;
            }
            else {
                if (currentFrame.isFinal()) {
                    return -1;
                }
                else {
                    currentFrame = null;
                    return read();
                }
            }
        }

        private void retransmitMaxData(QuicFrame lostFrame) {
            connection.send(new MaxStreamDataFrame(streamId, receiverMaxData), this::retransmitMaxData);
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
