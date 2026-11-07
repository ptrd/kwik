/*
 * Copyright © 2024, 2025, 2026 Peter Doornbosch
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

import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.Version;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Buffer for data to be sent on a stream. The buffer has a maximum size, and writing to it will block if the buffer is
 * full. The buffer is thread-safe for concurrent writes and reads, not for concurrent writes or concurrent reads.
 */
public class SendBuffer {

    public static final int DEFAULT_MAX_BUFFER_SIZE = 50 * 1024;

    // Send queue contains stream bytes to send in order. The position of the first byte buffer in the queue determines the next byte(s) to send.
    private final Queue<ByteBuffer> sendQueue;
    private final ByteBuffer END_OF_STREAM_MARKER = ByteBuffer.allocate(0);
    private final int maxBufferSize;
    private final AtomicInteger bufferedBytes;
    // Serializes appending to the send queue (data and end of stream marker) and guards the closed flag, so that no data
    // is appended after the end of stream marker. Readers only take it to signal notFull.
    private final ReentrantLock appendLock;
    private final Condition notFull;
    private volatile Thread blockingWriterThread;
    // Indicates the stream is reset or aborted, so a write that has not completed yet must fail.
    private volatile boolean writerInterrupted;
    // Indicates the end of stream marker has been added, so no more data can be added.
    // Thread safety: guarded by appendLock.
    private boolean closed;


    public SendBuffer(Integer sendBufferSize) {
        sendQueue = new ConcurrentLinkedDeque<>();
        if (sendBufferSize != null && sendBufferSize > 0) {
            maxBufferSize = sendBufferSize;
        }
        else {
            maxBufferSize = DEFAULT_MAX_BUFFER_SIZE;
        }
        bufferedBytes = new AtomicInteger();
        appendLock = new ReentrantLock();
        notFull = appendLock.newCondition();
    }

    /**
     * Writes data to the buffer. If there is not enough space in the buffer for all data, the method will block until
     * there is. Data is either written completely or not at all.
     * This method makes defensive copies of the data.
     * @param data  the data to write
     * @param offset  the offset in data of the first byte to write
     * @param length  the number of bytes to write; must not exceed the maximum buffer size, as the write would block forever
     * @throws IOException when the buffer is closed, also when it is closed while waiting for buffer space
     * @throws InterruptedException when the writer is interrupted by {@link #interruptBlockedWriter()}, also when that
     * happens before the write started, or when the writing thread is interrupted while waiting for buffer space
     */
    public void write(byte[] data, int offset, int length) throws IOException, InterruptedException {
        assert length <= maxBufferSize;
        // Data is added while holding the lock, so it can never end up after the end of stream marker (see close()).
        appendLock.lock();
        try {
            if (maxBufferSize - bufferedBytes.get() < length) {
                waitForBufferSpace(length);
            }
            if (writerInterrupted) {
                throw new InterruptedException();
            }
            if (closed) {
                throw new IOException("output stream already closed");
            }
            sendQueue.add(ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset + length)));
            bufferedBytes.getAndAdd(length);
        }
        finally {
            appendLock.unlock();
        }
    }

    private void waitForBufferSpace(int len) throws InterruptedException {
        assert appendLock.isHeldByCurrentThread();
        // The blocking writer must be registered before writerInterrupted is checked: interruptBlockedWriter sets the
        // flag before reading the blocking writer, so either this thread sees the flag, or it will be interrupted.
        blockingWriterThread = Thread.currentThread();
        try {
            while (maxBufferSize - bufferedBytes.get() < len && !closed && !writerInterrupted) {
                // Might throw InterruptedException, must be handled by caller
                notFull.await();
            }
            if (Thread.currentThread().isInterrupted()) {
                // When an interrupt races with a signal, await() can return normally with the interrupt status set
                // (instead of throwing InterruptedException); the interrupted write must not complete.
                throw new InterruptedException();
            }
        }
        finally {
            blockingWriterThread = null;
        }
    }

    public StreamFrame getStreamFrame(Version quicVersion, int streamId, long currentOffset, int maxBytesToSend) {
        int nrOfBytes = 0;
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
            }
            else {
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
        appendLock.lock();
        try {
            notFull.signal();
        }
        finally {
            appendLock.unlock();
        }
        if (nrOfBytes < maxBytesToSend) {
            // This can happen when not enough data is buffer to fill a stream frame, or length field is 1 byte (instead of 2 that was counted for)
            dataToSend = Arrays.copyOfRange(dataToSend, 0, nrOfBytes);
        }
        StreamFrame streamFrame = new StreamFrame(quicVersion, streamId, currentOffset, dataToSend, finalFrame);
        return streamFrame;
    }

    public int getAvailableBytes() {
        return bufferedBytes.get();
    }

    public boolean isEmpty() {
        return sendQueue.isEmpty();
    }

    /**
     * Adds the end of stream marker; after this, no more data can be written. A writer that is waiting for buffer
     * space will fail.
     */
    public void close() {
        appendLock.lock();
        try {
            closed = true;
            sendQueue.add(END_OF_STREAM_MARKER);
            notFull.signalAll();
        }
        finally {
            appendLock.unlock();
        }
    }

    /**
     * Makes a closed buffer accept data again; only to be used when the buffer is cleared, as that also removes the
     * end of stream marker.
     */
    public void reopen() {
        clear();
        appendLock.lock();
        try {
            closed = false;
        }
        finally {
            appendLock.unlock();
        }
    }

    public void clear() {
        sendQueue.clear();
        bufferedBytes.set(0);
        appendLock.lock();
        try {
            notFull.signal();
        }
        finally {
            appendLock.unlock();
        }
    }

    /**
     * Interrupts the writer that is waiting for buffer space and lets any write that has not completed yet fail.
     */
    public void interruptBlockedWriter() {
        writerInterrupted = true;
        Thread blocking = blockingWriterThread;
        if (blocking != null) {
            blocking.interrupt();
        }
    }

    public int getMaxSize() {
        return maxBufferSize;
    }

    public boolean hasData() {
        return !sendQueue.isEmpty();
    }
}
