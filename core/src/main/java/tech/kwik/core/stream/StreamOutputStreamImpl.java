/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.core.stream;

import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.frame.*;
import tech.kwik.core.log.Logger;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import static tech.kwik.core.common.EncryptionLevel.App;

class StreamOutputStreamImpl extends StreamOutputStream implements FlowControlUpdateListener {

    // Minimum stream frame size: frame type (1), stream id (1..8), offset (1..8), length (1..2), data (1...)
    // Note that in practice stream id and offset will seldom / never occupy 8 bytes, so the minimum leaves more room for data.
    private static final int MIN_FRAME_SIZE = 1 + 8 + 8 + 2 + 1;

    private final QuicStreamImpl quicStream;
    private final Object lock = new Object();

    private final SendBuffer sendBuffer;
    private final Logger log;
    private final int maxBufferSize;
    private final RetransmitBuffer retransmitBuffer;
    // Current offset is the offset of the next byte in the stream that will be sent.
    // Thread safety: only used by sender thread, so no synchronization needed.
    private long currentOffset;
    // Closed indicates whether the OutputStream is closed, meaning that no more bytes can be written by caller.
    // Thread safety: only use by caller
    private boolean closed;
    // Number of send requests that is queued, used to avoid multiple requests being queued (one is enough).
    private final AtomicInteger sendRequestsQueued;
    // Reset indicates whether the OutputStream has been reset.
    private volatile boolean reset;
    private volatile long resetErrorCode;
    // Reliable size of a reliable reset (RESET_STREAM_AT): the amount of stream data that must still be delivered
    // despite the reset. A negative value indicates the reset (if any) is a plain reset.
    private volatile long reliableResetSize = -1;
    // Total number of bytes written to this output stream, used to validate the reliable size of a reliable reset.
    // Thread safety: written by caller thread, read by the thread calling reset (which can be a different one).
    private volatile long totalWritten;
    // Guards stream reset, to ensure that of multiple (concurrent) resets only one is effectuated.
    private final ReentrantLock resetLock = new ReentrantLock();
    // Whether all stream data up to the reliable size has been sent (and remaining data discarded).
    // Thread safety: only used by sender thread.
    private boolean reliableResetCompleted;
    // Final size sent in the RESET_STREAM_AT frame; must never change once determined.
    // Thread safety: only used by sender thread.
    private long resetFinalSize = -1;
    // Stream offset at which the stream was last blocked, for detecting the first time stream is blocked at a certain offset.
    private long blockedOffset;
    protected final FlowControl flowController;
    private volatile boolean aborted;

    StreamOutputStreamImpl(QuicStreamImpl quicStream, Integer sendBufferSize, FlowControl flowControl, Logger log) {
        this.quicStream = quicStream;
        flowController = flowControl;
        sendBuffer = new SendBuffer(sendBufferSize);
        this.log = log;
        maxBufferSize = sendBuffer.getMaxSize();
        retransmitBuffer = new RetransmitBuffer();
        flowController.streamOpened(quicStream);
        sendRequestsQueued = new AtomicInteger(0);

        flowController.register(quicStream, this);
    }

    @Override
    public void write(byte[] data) throws IOException {
        write(data, 0, data.length);
    }

    @Override
    public void write(byte[] data, int off, int len) throws IOException {
        checkState();
        try {
            if (len <= maxBufferSize) {
                sendBuffer.write(data, off, len);
                totalWritten += len;
            }
            else {
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
        }
        catch (InterruptedException e) {
            String msg = "write failed because stream was " + (closed? "closed" : (reset? "reset" : "aborted"));
            throw new InterruptedIOException(msg);
        }

        scheduleSendStreamFrameRequest(true);
    }

    private void scheduleSendStreamFrameRequest(boolean flush) {
        int queued = sendRequestsQueued.get();
        if (queued == 0) {
            // This is a race condition, but not a problem when one superfluous send request is queued.
            quicStream.connection.send(this::sendStreamFrame, MIN_FRAME_SIZE, getEncryptionLevel(), this::retransmitStreamFrame, flush);
            sendRequestsQueued.incrementAndGet();
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
            sendBuffer.close();
            closed = true;
            scheduleSendStreamFrameRequest(true);
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

    QuicFrame sendStreamFrame(int maxFrameSize) {
        if (reset && reliableResetSize < 0) {
            // Plain reset: no stream data is sent anymore.
            return null;
        }
        // As this class always queues a send stream frame request by registering a callback, the callback can be used to keep track of the number of requests that are actually queued.
        sendRequestsQueued.decrementAndGet();

        checkReliableResetCompleted();

        StreamFrame streamFrame = null;
        if (retransmitBuffer.hasDataToRetransmit()) {
            streamFrame = retransmitBuffer.getFrameToRetransmit(maxFrameSize);
            quicStream.log.recovery("Retransmitted lost stream frame " + streamFrame);
            assert (streamFrame != null);
        }
        else if (sendBuffer.hasData()) {
            long flowControlLimit = flowController.getFlowControlLimit(quicStream);
            assert (flowControlLimit >= currentOffset);

            int maxBytesToSend = sendBuffer.getAvailableBytes();
            if (reset && reliableResetSize >= 0) {
                // Reliable reset: send no data beyond the reliable size. The current offset can (only) be beyond the
                // reliable size when the reset happened concurrently with this method execution; in that case no data
                // is sent at all and a next invocation (queued by the reset) will discard the remaining data.
                maxBytesToSend = (int) Long.min(maxBytesToSend, Long.max(0, reliableResetSize - currentOffset));
            }
            if (flowControlLimit > currentOffset || maxBytesToSend == 0) {
                StreamFrame dummy = new StreamFrame(quicStream.quicVersion, quicStream.streamId, currentOffset, new byte[0], false);
                maxBytesToSend = Integer.min(maxBytesToSend, maxFrameSize - dummy.getFrameLength() - 1);  // Take one byte extra for length field var int
                int maxAllowedByFlowControl = (int) (flowController.increaseFlowControlLimit(quicStream, currentOffset + maxBytesToSend) - currentOffset);
                maxBytesToSend = Integer.min(maxAllowedByFlowControl, maxBytesToSend);

                streamFrame = sendBuffer.getStreamFrame(quicStream.quicVersion, quicStream.streamId, currentOffset, maxBytesToSend);
                if (streamFrame != null) {
                    currentOffset += streamFrame.getLength();
                    checkReliableResetCompleted();
                }

                if (streamFrame != null && streamFrame.isFinal()) {
                    finalFrameSent();
                }
            }
            else {
                // So flowControlLimit <= currentOffset, i.e. no flow control credits left.
                // Check if this condition hasn't been handled before
                if (currentOffset != blockedOffset) {
                    // Not handled before, remember this offset, so this isn't executed twice for the same offset
                    blockedOffset = currentOffset;
                    log.stream(quicStream + " blocked at " + blockedOffset);
                    // And let peer know
                    // https://www.rfc-editor.org/rfc/rfc9000.html#name-data-flow-control
                    // "A sender SHOULD send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the receiver
                    //  that it has data to write but is blocked by flow control limits."
                    quicStream.connection.send(this::sendBlockReason, StreamDataBlockedFrame.getMaxSize(quicStream.streamId), App, this::retransmitBlockReason, true);
                    // As the stream is blocked, no need to queue a new send request.
                    return null;
                }
            }
        }
        if (streamFrame != null && (sendBuffer.hasData() || retransmitBuffer.hasDataToRetransmit())) {
            // There is more to send, so queue a new send request.
            scheduleSendStreamFrameRequest(true);
        }

        return streamFrame;
    }

    /**
     * Checks whether all stream data up to the reliable size of a reliable reset has been sent, and if so, discards
     * the remaining data and stops flow control (delivery of the data already sent is guaranteed by retransmission,
     * which does not need flow control).
     * Thread safety: is called from sender thread only.
     */
    private void checkReliableResetCompleted() {
        if (reset && reliableResetSize >= 0 && currentOffset >= reliableResetSize && !reliableResetCompleted) {
            reliableResetCompleted = true;
            // https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-07.html#section-5
            // "When using a RESET_STREAM_AT frame, the initiator MUST guarantee reliable delivery of stream data of at
            //  least Reliable Size bytes."
            sendBuffer.clear();
            // This situation is similar to the final frame being sent, so stop flow control and close the output stream.
            stopFlowControl();
            quicStream.outputClosed();
        }
    }

    protected void finalFrameSent() {
        stopFlowControl();
        quicStream.outputClosed();
    }

    @Override
    public void streamNotBlocked(int streamId) {
        log.stream(quicStream + " unblocked at " + currentOffset);
        // Stream might have been blocked (or it might have filled the flow control window exactly), queue send request
        // and let sendFrame method determine whether there is more to send or not.
        scheduleSendStreamFrameRequest(false);  // No need to flush, as this is called while processing received message
    }

    void interruptBlockingThread() {
        sendBuffer.interruptBlockedWriter();
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

    private void retransmitBlockReason(QuicFrame quicFrame) {
        quicStream.connection.send(this::sendBlockReason, StreamDataBlockedFrame.getMaxSize(quicStream.streamId), App, this::retransmitBlockReason, true);
    }

    private void retransmitStreamFrame(QuicFrame frame) {
        assert (frame instanceof StreamFrame);
        // When reset, stream data is not retransmitted, except for a reliable reset, which guarantees delivery of
        // stream data up to the reliable size:
        // https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-07.html#section-5
        // "If STREAM frames containing data up to that byte offset are lost, the initiator MUST retransmit this data"
        if (!reset || reliableResetSize >= 0 && ((StreamFrame) frame).getOffset() < reliableResetSize) {
            retransmitBuffer.add((StreamFrame) frame);
            scheduleSendStreamFrameRequest(true);
        }
    }

    protected EncryptionLevel getEncryptionLevel() {
        return App;
    }

    // Very confusing name: this has nothing to do with resetting the stream as the reset method does!
    protected void resetOutputStream() {
        closed = false;
        // TODO: this is currently not thread safe, see comment in EarlyDataStream how to fix.
        restart();
    }

    private void restart() {
        currentOffset = 0;
        sendBuffer.clear();
        sendRequestsQueued.set(0);
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9000.html#name-operations-on-streams
     * "reset the stream (abrupt termination), resulting in a RESET_STREAM frame (Section 19.4) if the stream was
     * not already in a terminal state."
     *
     * @param errorCode
     */
    protected void reset(long errorCode) {
        resetLock.lock();
        try {
            if (!closed && !reset) {
                reset = true;
                resetErrorCode = errorCode;
                // Interrupt a blocked writer before discarding the data: discarding frees buffer space, which would wake
                // up the writer and let its write complete normally, but after a reset a pending write should fail.
                interruptBlockingThread();
                discardAllData();
                // Use sender callback to ensure current offset used in reset frame is accessed by sender thread.
                quicStream.connection.send(this::createResetFrame, ResetStreamFrame.getMaximumFrameSize(quicStream.streamId, errorCode), App, this::retransmitResetFrame, true);
                quicStream.outputClosed();
            }
        }
        finally {
            resetLock.unlock();
        }
    }

    /**
     * https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-07.html
     * "A sender that wants to reset a stream but also deliver some bytes to the receiver sends a RESET_STREAM_AT frame
     *  with the Reliable Size field specifying the amount of data to be delivered."
     *
     * @param errorCode
     * @param reliableSize
     */
    protected void reset(long errorCode, long reliableSize) {
        if (reliableSize < 0) {
            throw new IllegalArgumentException("reliable size must not be negative");
        }
        if (!quicStream.connection.canUseReliableStreamReset()) {
            throw new IllegalStateException("peer does not support reliable stream reset");
        }
        if (reliableSize > totalWritten) {
            throw new IllegalArgumentException("reliable size cannot exceed the number of bytes written to the stream");
        }
        if (reliableSize == 0) {
            // https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-07.html#section-5
            // "A RESET_STREAM_AT frame with this value is logically equivalent to a RESET_STREAM frame"
            reset(errorCode);
            return;
        }
        resetLock.lock();
        try {
            if (!closed && !reset) {
                resetErrorCode = errorCode;
                reliableResetSize = reliableSize;
                reset = true;
                // Use sender callback to ensure current offset used in reset frame is accessed by sender thread.
                quicStream.connection.send(this::createResetStreamAtFrame, ResetStreamAtFrame.getMaximumFrameSize(quicStream.streamId, errorCode), App, this::retransmitResetFrame, true);
                // Data up to the reliable size must still be sent; queue a send request in case none is pending.
                scheduleSendStreamFrameRequest(true); // Necessary to ensure checkReliableResetCompleted is called after reset.
                interruptBlockingThread();
            }
        }
        finally {
            resetLock.unlock();
        }
    }

    private void discardAllData() {
        sendBuffer.clear();
    }

    private QuicFrame createResetFrame(int maxFrameSize) {
        assert (reset == true);
        return new ResetStreamFrame(quicStream.streamId, resetErrorCode, currentOffset);
    }

    private QuicFrame createResetStreamAtFrame(int maxFrameSize) {
        // Thread safety: is called from sender thread only.
        assert (reset == true);
        if (resetFinalSize < 0) {
            // Data up to the reliable size will still be sent (and sending is capped at the reliable size), so the
            // final size is known already, even when not all data has been sent yet.
            resetFinalSize = Long.max(currentOffset, reliableResetSize);
        }
        return new ResetStreamAtFrame(quicStream.streamId, resetErrorCode, resetFinalSize, reliableResetSize);
    }

    private void retransmitResetFrame(QuicFrame frame) {
        assert (frame instanceof ResetStreamFrame || frame instanceof ResetStreamAtFrame);
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
