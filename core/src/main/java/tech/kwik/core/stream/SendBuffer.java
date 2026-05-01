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

import tech.kwik.core.StreamWriteListener;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.Version;

import java.io.IOException;
import java.nio.ByteBuffer;
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

    private final QuicStreamImpl stream;

    // Send queue contains stream bytes to send in order. The position of the first byte buffer in the queue determines the next byte(s) to send.
    private final Queue<ByteBuffer> sendQueue;
    private final ByteBuffer END_OF_STREAM_MARKER = ByteBuffer.allocate(0);
    private final int maxBufferSize;
    private final AtomicInteger bufferedBytes;
    private final ReentrantLock bufferLock;
    private final Condition notFull;
    private volatile Thread blockingWriterThread;

    private volatile boolean closed = false;

    private volatile int lastReportedAvail = Integer.MIN_VALUE;
    private volatile boolean lastReportedWritable = true;

    public SendBuffer(QuicStreamImpl stream, Integer sendBufferSize) {
        this.stream = stream;
        sendQueue = new ConcurrentLinkedDeque<>();
        if (sendBufferSize != null && sendBufferSize > 0) {
            maxBufferSize = sendBufferSize;
        }
        else {
            maxBufferSize = 50 * 1024;
        }
        bufferedBytes = new AtomicInteger();
        bufferLock = new ReentrantLock();
        notFull = bufferLock.newCondition();
    }

    public void notifyCanWrite(boolean force) {
		StreamWriteListener listener = (stream != null && stream.connection != null)
                ? stream.connection.getStreamWriteListener() :
                null;
        if (listener == null) return;
        else if (stream.isOutputClosed()) return;

        int avail = getAvailableBytes();
        boolean canWrite = !closed && avail > 0;
        int report = canWrite ? avail : 0;

        if (force || report != lastReportedAvail || canWrite != lastReportedWritable) {
            lastReportedAvail = report;
            lastReportedWritable = canWrite;
            this.stream.listenerPool.execute(() -> {
				if (stream.isOutputClosed()) return;
				listener.write(stream, report);
			});
        }
    }

    /**
     * Writes data to the buffer. If the buffer is full, the method will block until there is enough space in the buffer.
     * This method makes defensive copies of the data.
     */
    public void write(byte[] data, int off, int len) throws IOException, InterruptedException {
        int availableBufferSpace = maxBufferSize - bufferedBytes.get();
        if (len > availableBufferSpace) {
            // Wait for enough buffer space to become available
            bufferLock.lock();
            blockingWriterThread = Thread.currentThread();
            try {
                while (maxBufferSize - bufferedBytes.get() < len) {
                    if (Thread.currentThread().isInterrupted()) {
                        throw new InterruptedException();
                    }
                    // Might throw InterruptedException, must be handled by caller
                    notFull.await();
                }
            }
            finally {
                blockingWriterThread = null;
                bufferLock.unlock();
            }
        }

        sendQueue.add(ByteBuffer.wrap(java.util.Arrays.copyOfRange(data, off, off + len)));
        bufferedBytes.getAndAdd(len);

        notifyCanWrite(false);
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
        bufferLock.lock();
        try {
            notFull.signal();
        }
        finally {
            bufferLock.unlock();
        }

        notifyCanWrite(false);

        if (nrOfBytes < maxBytesToSend) {
            // This can happen when not enough data is buffer to fill a stream frame, or length field is 1 byte (instead of 2 that was counted for)
            dataToSend = java.util.Arrays.copyOfRange(dataToSend, 0, nrOfBytes);
        }

        return new StreamFrame(quicVersion, streamId, currentOffset, dataToSend, finalFrame);
    }

    public int getBufferedBytes() {
        return bufferedBytes.get();
    }
    public int getAvailableBytes() {
        return getMaxSize() - getBufferedBytes();
    }

    public boolean isEmpty() {
        return sendQueue.isEmpty();
    }

    public void clear() {
        sendQueue.clear();
        bufferedBytes.set(0);
        closed = false;
        notifyCanWrite(true);
    }

    public void close() {
        if (closed) return;
        closed = true;
        sendQueue.add(END_OF_STREAM_MARKER);
        notifyCanWrite(true);
    }

    public void interruptBlockedWriter() {
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
