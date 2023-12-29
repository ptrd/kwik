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

import net.luminis.quic.core.EncryptionLevel;
import net.luminis.quic.frame.DataBlockedFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.ResetStreamFrame;
import net.luminis.quic.frame.StreamDataBlockedFrame;
import net.luminis.quic.frame.StreamFrame;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import static net.luminis.quic.core.EncryptionLevel.App;

class StreamOutputStreamImpl extends StreamOutputStream implements FlowControlUpdateListener {

    // Minimum stream frame size: frame type (1), stream id (1..8), offset (1..8), length (1..2), data (1...)
    // Note that in practice stream id and offset will seldom / never occupy 8 bytes, so the minimum leaves more room for data.
    private static final int MIN_FRAME_SIZE = 1 + 8 + 8 + 2 + 1;

    private final QuicStreamImpl quicStream;
    private final ByteBuffer END_OF_STREAM_MARKER = ByteBuffer.allocate(0);
    private final Object lock = new Object();

    // Send queue contains stream bytes to send in order. The position of the first byte buffer in the queue determines the next byte(s) to send.
    private Queue<ByteBuffer> sendQueue = new ConcurrentLinkedDeque<>();
    private final int maxBufferSize;
    private final AtomicInteger bufferedBytes;
    private final ReentrantLock bufferLock;
    private final Condition notFull;
    // Current offset is the offset of the next byte in the stream that will be sent.
    // Thread safety: only used by sender thread, so no synchronization needed.
    private long currentOffset;
    // Closed indicates whether the OutputStream is closed, meaning that no more bytes can be written by caller.
    // Thread safety: only use by caller
    private boolean closed;
    // Send request queued indicates whether a request to send a stream frame is queued with the sender. Is used to avoid multiple requests being queued.
    // Thread safety: read/set by caller and by sender thread, so must be synchronized; guarded by lock
    private volatile boolean sendRequestQueued;
    // Reset indicates whether the OutputStream has been reset.
    private volatile boolean reset;
    private volatile long resetErrorCode;
    // Stream offset at which the stream was last blocked, for detecting the first time stream is blocked at a certain offset.
    private long blockedOffset;
    private volatile Thread blockingWriterThread;
    protected final FlowControl flowController;
    private volatile boolean aborted;


    StreamOutputStreamImpl(QuicStreamImpl quicStream, Integer sendBufferSize, FlowControl flowControl) {
        this.quicStream = quicStream;
        flowController = flowControl;
        bufferedBytes = new AtomicInteger();
        bufferLock = new ReentrantLock();
        notFull = bufferLock.newCondition();
        if (sendBufferSize != null && sendBufferSize > 0) {
            maxBufferSize = sendBufferSize;
        } else {
            maxBufferSize = 50 * 1024;
        }

        flowController.streamOpened(quicStream);

        flowController.register(quicStream, this);
    }

    @Override
    public void write(byte[] data) throws IOException {
        write(data, 0, data.length);
    }

    @Override
    public void write(byte[] data, int off, int len) throws IOException {
        checkState();
        if (len > maxBufferSize) {
            // Buffering all would break the contract (because this method copies _all_ data) but splitting and
            // writing smaller chunks (and waiting for each individual chunk to be buffered successfully) does not.
            int halfBuffersize = maxBufferSize / 2;
            int times = len / halfBuffersize;
            for (int i = 0; i < times; i++) {
                // Each individual write will probably block, but by splitting the writes in half buffer sizes
                // avoids that the buffer needs to be emptied completely before a new block can be added (which
                // could have severed negative impact on performance as the sender might have to wait for the caller
                // to fill the buffer again).
                write(data, off + i * halfBuffersize, halfBuffersize);
            }
            int rest = len % halfBuffersize;
            if (rest > 0) {
                write(data, off + times * halfBuffersize, rest);
            }
            return;
        }

        int availableBufferSpace = maxBufferSize - bufferedBytes.get();
        if (len > availableBufferSpace) {
            // Wait for enough buffer space to become available
            bufferLock.lock();
            blockingWriterThread = Thread.currentThread();
            try {
                while (maxBufferSize - bufferedBytes.get() < len) {
                    checkState();
                    try {
                        notFull.await();
                    }
                    catch (InterruptedException e) {
                        String msg = "write failed because stream was " + (closed? "closed" : (reset? "reset" : "aborted"));
                        throw new InterruptedIOException(msg);
                    }
                }
            } finally {
                blockingWriterThread = null;
                bufferLock.unlock();
            }
        }

        sendQueue.add(ByteBuffer.wrap(Arrays.copyOfRange(data, off, off + len)));
        bufferedBytes.getAndAdd(len);
        synchronized (lock) {
            if (!sendRequestQueued) {
                sendRequestQueued = true;
                quicStream.connection.send(this::sendFrame, MIN_FRAME_SIZE, getEncryptionLevel(), this::retransmitStreamFrame, true);
            }
        }
    }

    @Override
    public void write(int dataByte) throws IOException {
        // Terrible for performance of course, but that is calling this method anyway.
        byte[] data = new byte[]{(byte) dataByte};
        write(data, 0, 1);
    }

    @Override
    public void flush() throws IOException {
        checkState();
        // No-op, this implementation sends data as soon as possible.
    }

    @Override
    public void close() throws IOException {
        if (!closed && !aborted && !reset) {
            sendQueue.add(END_OF_STREAM_MARKER);
            closed = true;
            synchronized (lock) {
                if (!sendRequestQueued) {
                    sendRequestQueued = true;
                    quicStream.connection.send(this::sendFrame, MIN_FRAME_SIZE, getEncryptionLevel(), this::retransmitStreamFrame, true);
                }
            }
        }
    }

    private void checkState() throws IOException {
        if (closed || reset) {
            throw new IOException("output stream " + (closed ? "already closed" : "is reset"));
        }
        if (aborted) {
            throw new IOException("output aborted because connection is closed");
        }
    }

    QuicFrame sendFrame(int maxFrameSize) {
        if (reset) {
            return null;
        }
        synchronized (lock) {
            sendRequestQueued = false;
        }

        if (!sendQueue.isEmpty()) {
            long flowControlLimit = flowController.getFlowControlLimit(quicStream);
            assert (flowControlLimit >= currentOffset);

            int maxBytesToSend = bufferedBytes.get();
            if (flowControlLimit > currentOffset || maxBytesToSend == 0) {
                int nrOfBytes = 0;
                StreamFrame dummy = new StreamFrame(quicStream.quicVersion, quicStream.streamId, currentOffset, new byte[0], false);
                maxBytesToSend = Integer.min(maxBytesToSend, maxFrameSize - dummy.getFrameLength() - 1);  // Take one byte extra for length field var int
                int maxAllowedByFlowControl = (int) (flowController.increaseFlowControlLimit(quicStream, currentOffset + maxBytesToSend) - currentOffset);
                maxBytesToSend = Integer.min(maxAllowedByFlowControl, maxBytesToSend);

                byte[] dataToSend = new byte[maxBytesToSend];
                boolean finalFrame = false;
                while (nrOfBytes < maxBytesToSend && !sendQueue.isEmpty()) {
                    ByteBuffer buffer = sendQueue.peek();
                    int position = nrOfBytes;
                    if (buffer.remaining() <= maxBytesToSend - nrOfBytes) {
                        // All bytes remaining in buffer will fit in stream frame
                        nrOfBytes += buffer.remaining();
                        buffer.get(dataToSend, position, buffer.remaining());
                        sendQueue.poll();
                    } else {
                        // Just part of the buffer will fit in (and will fill up) the stream frame
                        buffer.get(dataToSend, position, maxBytesToSend - nrOfBytes);
                        nrOfBytes = maxBytesToSend;  // Short form of: nrOfBytes += (maxBytesToSend - nrOfBytes)
                    }
                }
                if (!sendQueue.isEmpty() && sendQueue.peek() == END_OF_STREAM_MARKER) {
                    finalFrame = true;
                    sendQueue.poll();
                }
                if (nrOfBytes == 0 && !finalFrame) {
                    // Nothing to send really
                    return null;
                }

                bufferedBytes.getAndAdd(-1 * nrOfBytes);
                bufferLock.lock();
                try {
                    notFull.signal();
                } finally {
                    bufferLock.unlock();
                }

                if (nrOfBytes < maxBytesToSend) {
                    // This can happen when not enough data is buffer to fill a stream frame, or length field is 1 byte (instead of 2 that was counted for)
                    dataToSend = Arrays.copyOfRange(dataToSend, 0, nrOfBytes);
                }
                StreamFrame streamFrame = new StreamFrame(quicStream.quicVersion, quicStream.streamId, currentOffset, dataToSend, finalFrame);
                currentOffset += nrOfBytes;

                if (!sendQueue.isEmpty()) {
                    synchronized (lock) {
                        sendRequestQueued = true;
                    }
                    // There is more to send, so queue a new send request.
                    quicStream.connection.send(this::sendFrame, MIN_FRAME_SIZE, getEncryptionLevel(), this::retransmitStreamFrame, true);
                }

                if (streamFrame.isFinal()) {
                    finalFrameSent();
                }
                return streamFrame;
            } else {
                // So flowControlLimit <= currentOffset
                // Check if this condition hasn't been handled before
                if (currentOffset != blockedOffset) {
                    // Not handled before, remember this offset, so this isn't executed twice for the same offset
                    blockedOffset = currentOffset;
                    // And let peer know
                    // https://www.rfc-editor.org/rfc/rfc9000.html#name-data-flow-control
                    // "A sender SHOULD send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the receiver
                    //  that it has data to write but is blocked by flow control limits."
                    quicStream.connection.send(this::sendBlockReason, StreamDataBlockedFrame.getMaxSize(quicStream.streamId), App, this::retransmitSendBlockReason, true);
                }
            }
        }
        return null;
    }

    protected void finalFrameSent() {
        stopFlowControl();
        quicStream.outputClosed();
    }

    @Override
    public void streamNotBlocked(int streamId) {
        // Stream might have been blocked (or it might have filled the flow control window exactly), queue send request
        // and let sendFrame method determine whether there is more to send or not.
        quicStream.connection.send(this::sendFrame, MIN_FRAME_SIZE, getEncryptionLevel(), this::retransmitStreamFrame, false);  // No need to flush, as this is called while processing received message
    }

    void interruptBlockingThread() {
        Thread blocking = blockingWriterThread;
        if (blocking != null) {
            blocking.interrupt();
        }
    }

    /**
     * Sends StreamDataBlockedFrame or DataBlockedFrame to the peer, provided the blocked condition is still true.
     *
     * @param maxFrameSize
     * @return
     */
    private QuicFrame sendBlockReason(int maxFrameSize) {
        // Retrieve actual block reason; could be "none" when an update has been received in the meantime.
        BlockReason blockReason = flowController.getFlowControlBlockReason(quicStream);
        QuicFrame frame = null;
        switch (blockReason) {
            case STREAM_DATA_BLOCKED:
                frame = new StreamDataBlockedFrame(quicStream.quicVersion, quicStream.streamId, currentOffset);
                break;
            case DATA_BLOCKED:
                frame = new DataBlockedFrame(flowController.getConnectionDataLimit());
                break;
        }
        return frame;
    }

    private void retransmitSendBlockReason(QuicFrame quicFrame) {
        quicStream.connection.send(this::sendBlockReason, StreamDataBlockedFrame.getMaxSize(quicStream.streamId), App, this::retransmitSendBlockReason, true);
    }

    private void retransmitStreamFrame(QuicFrame frame) {
        assert (frame instanceof StreamFrame);
        if (!reset) {
            quicStream.connection.send(frame, this::retransmitStreamFrame);
            quicStream.log.recovery("Retransmitted lost stream frame " + frame);
        }
    }

    protected EncryptionLevel getEncryptionLevel() {
        return App;
    }

    protected void resetOutputStream() {
        closed = false;
        // TODO: this is currently not thread safe, see comment in EarlyDataStream how to fix.
        restart();
    }

    private void restart() {
        currentOffset = 0;
        sendQueue.clear();
        sendRequestQueued = false;
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9000.html#name-operations-on-streams
     * "reset the stream (abrupt termination), resulting in a RESET_STREAM frame (Section 19.4) if the stream was
     * not already in a terminal state."
     *
     * @param errorCode
     */
    protected void reset(long errorCode) {
        if (!closed && !reset) {
            reset = true;
            resetErrorCode = errorCode;
            discardAllData();
            // Use sender callback to ensure current offset used in reset frame is accessed by sender thread.
            quicStream.connection.send(this::createResetFrame, ResetStreamFrame.getMaximumFrameSize(quicStream.streamId, errorCode), App, this::retransmitResetFrame, true);
            interruptBlockingThread();
            quicStream.outputClosed();
        }
    }

    private void discardAllData() {
        sendQueue.clear();
        bufferedBytes.set(0);
    }

    private QuicFrame createResetFrame(int maxFrameSize) {
        assert (reset == true);
        return new ResetStreamFrame(quicStream.streamId, resetErrorCode, currentOffset);
    }

    private void retransmitResetFrame(QuicFrame frame) {
        assert (frame instanceof ResetStreamFrame);
        quicStream.connection.send(frame, this::retransmitResetFrame);
    }

    protected void stopFlowControl() {
        // Done! Retransmissions may follow, but don't need flow control.
        flowController.unregister(quicStream);
        flowController.streamClosed(quicStream);
    }

    void abort() {
        aborted = true;
        interruptBlockingThread();
    }
}
