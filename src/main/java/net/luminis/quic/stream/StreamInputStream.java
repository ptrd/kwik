/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
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

import net.luminis.quic.core.TransportError;
import net.luminis.quic.frame.MaxStreamDataFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.StopSendingFrame;
import net.luminis.quic.frame.StreamFrame;

import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;

import static net.luminis.quic.QuicConstants.TransportErrorCode.FLOW_CONTROL_ERROR;

/**
 * Input stream for reading data received by the QUIC stream.
 */
class StreamInputStream extends InputStream {

    protected static long waitForNextFrameTimeout = Long.MAX_VALUE;

    protected static final float receiverMaxDataIncrementFactor = 0.10f;

    private final QuicStreamImpl quicStream;
    private volatile boolean closed;
    private volatile boolean reset;
    private volatile Thread blockingReaderThread;
    private final ReceiveBufferImpl receiveBuffer;
    private final Object addMonitor = new Object();
    private long lastCommunicatedMaxData;
    private final long receiverMaxDataIncrement;
    private long largestOffsetReceived;
    private long receiverFlowControlLimit;
    private volatile boolean aborted;

    public StreamInputStream(QuicStreamImpl quicStream) {
        this.quicStream = quicStream;
        receiveBuffer = new ReceiveBufferImpl();

        receiverFlowControlLimit = quicStream.connection.getInitialMaxStreamData();
        lastCommunicatedMaxData = receiverFlowControlLimit;
        receiverMaxDataIncrement = (long) (receiverFlowControlLimit * receiverMaxDataIncrementFactor);
    }

    void add(StreamFrame frame) throws TransportError {
        synchronized (addMonitor) {
            if (frame.getUpToOffset() > receiverFlowControlLimit) {
                throw new TransportError(FLOW_CONTROL_ERROR);
            }
            receiveBuffer.add(frame);
            largestOffsetReceived = Long.max(largestOffsetReceived, frame.getUpToOffset());
            addMonitor.notifyAll();
        }
    }

    long getCurrentReceiveOffset() {
        return largestOffsetReceived;
    }

    @Override
    public int available() throws IOException {
        long bytesAvailable = receiveBuffer.bytesAvailable();
        if (bytesAvailable > Integer.MAX_VALUE) {
            return Integer.MAX_VALUE;
        } else {
            return (int) bytesAvailable;
        }
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
        } else if (bytesRead < 0) {
            // End of stream
            return -1;
        } else {
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
        if (len == 0) {
            return 0;
        }
        Instant readAttemptStarted = Instant.now();
        long waitPeriod = waitForNextFrameTimeout;
        while (true) {
            if (aborted || closed || reset) {
                throw new IOException(aborted ? "Connection closed" : closed ? "Stream closed" : "Stream reset by peer");
            }

            synchronized (addMonitor) {
                try {
                    blockingReaderThread = Thread.currentThread();

                    int bytesRead = receiveBuffer.read(ByteBuffer.wrap(buffer, offset, len));
                    if (bytesRead > 0) {
                        updateAllowedFlowControl(bytesRead);
                        return bytesRead;
                    } else if (bytesRead < 0) {
                        // End of stream
                        allDataRead();
                        return -1;
                    }

                    // Nothing read: block until bytes can be read, read timeout or abort
                    try {
                        addMonitor.wait(waitPeriod);
                    } catch (InterruptedException e) {
                        // Nothing to do here: read will be abort in next loop iteration with IOException
                    }
                } finally {
                    blockingReaderThread = null;
                }
            }

            if (receiveBuffer.bytesAvailable() == 0) {
                long waited = Duration.between(readAttemptStarted, Instant.now()).toMillis();
                if (waited > waitForNextFrameTimeout) {
                    throw new SocketTimeoutException("Read timeout on stream " + quicStream.streamId + "; read up to " + receiveBuffer.readOffset());
                } else {
                    waitPeriod = Long.max(1, waitForNextFrameTimeout - waited);
                }
            }
        }
    }

    private void allDataRead() {
        quicStream.inputClosed();
    }

    @Override
    public void close() throws IOException {
        // Note that QUIC specification does not define application protocol error codes.
        // By absence of an application specified error code, the arbitrary code 0 is used.
        stopInput(0);
    }

    void stopInput(long errorCode) {
        if (!receiveBuffer.allDataReceived()) {
            quicStream.connection.send(new StopSendingFrame(quicStream.quicVersion, quicStream.streamId, errorCode), this::retransmitStopInput, true);
        }
        closed = true;
        Thread blockingReader = blockingReaderThread;
        if (blockingReader != null) {
            blockingReader.interrupt();
        }
    }

    private void retransmitStopInput(QuicFrame lostFrame) {
        assert (lostFrame instanceof StopSendingFrame);

        if (!receiveBuffer.allDataReceived()) {
            quicStream.connection.send(lostFrame, this::retransmitStopInput);
        }
    }

    private void updateAllowedFlowControl(int bytesRead) {
        // Slide flow control window forward (with as many bytes as are read)
        receiverFlowControlLimit += bytesRead;
        quicStream.updateConnectionFlowControl(bytesRead);
        // Avoid sending flow control updates with every single read; check diff with last send max data
        if (receiverFlowControlLimit - lastCommunicatedMaxData > receiverMaxDataIncrement) {
            quicStream.connection.send(new MaxStreamDataFrame(quicStream.streamId, receiverFlowControlLimit), this::retransmitMaxData, true);
            lastCommunicatedMaxData = receiverFlowControlLimit;
        }
    }

    private void retransmitMaxData(QuicFrame lostFrame) {
        quicStream.connection.send(new MaxStreamDataFrame(quicStream.streamId, receiverFlowControlLimit), this::retransmitMaxData);
        quicStream.log.recovery("Retransmitted max stream data, because lost frame " + lostFrame);
    }

    void terminate(long errorCode, long finalSize) {
        if (!aborted && !closed && !reset) {
            reset = true;
            Thread blockingReader = blockingReaderThread;
            if (blockingReader != null) {
                blockingReader.interrupt();
            }
        }
    }

    void abort() {
        aborted = true;
        interruptBlockingThread();
    }

    void interruptBlockingThread() {
        Thread readerBlocking = blockingReaderThread;
        if (readerBlocking != null) {
            readerBlocking.interrupt();
        }
    }
}
