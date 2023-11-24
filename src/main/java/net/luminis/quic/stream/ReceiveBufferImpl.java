/*
 * Copyright © 2023 Peter Doornbosch
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

import java.nio.ByteBuffer;
import java.util.NavigableSet;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentSkipListSet;

/**
 * A receive buffer imlementation.
 * This implementation is not thread-safe, but concurrent access by separate producer and consumer threads is supported,
 * under the condition that the add method is never called concurrently and the collection of read methods (i.e. all
 * other methods) are never called concurrently.
 * These conditions are met in the practical case that:
 * - there is only one producer thread and only one consumer thread
 * - the producer thread only calls the add method
 * - the consumer thread never calls the add method
 */
public class ReceiveBufferImpl implements ReceiveBuffer {

    private NavigableSet<StreamElement> outOfOrderFrames = new ConcurrentSkipListSet<>();
    private Queue<StreamElement> contiguousFrames = new ConcurrentLinkedQueue<>();
    private volatile long contiguousUpToOffset = 0;
    private volatile long readUpToOffset = 0;
    private volatile long streamEndOffset = -1;

    @Override
    public long bytesAvailable() {
        return contiguousUpToOffset - readUpToOffset;
    }

    @Override
    public boolean allRead() {
        return streamEndOffset >= 0 && readUpToOffset == streamEndOffset;
    }

    @Override
    public int read(ByteBuffer buffer) {
        if (allRead()) {
            return -1;
        }

        int totalBytesRead = 0;
        StreamElement nextFrame = contiguousFrames.peek();
        while (nextFrame != null && buffer.hasRemaining()) {
            int bytesToRead = (int) Long.min(buffer.remaining(), nextFrame.getUpToOffset() - readUpToOffset);
            buffer.put(nextFrame.getStreamData(), (int) (readUpToOffset - nextFrame.getOffset()), bytesToRead);
            readUpToOffset += bytesToRead;
            totalBytesRead += bytesToRead;
            if (readUpToOffset == nextFrame.getUpToOffset()) {
                contiguousFrames.remove();
                nextFrame = contiguousFrames.peek();
            }
        }
        return totalBytesRead;
    }

    @Override
    public boolean allDataReceived() {
        return streamEndOffset >= 0 && contiguousUpToOffset == streamEndOffset;
    }

    @Override
    public long readOffset() {
        return readUpToOffset;
    }

    @Override
    public boolean add(StreamElement frame) {
        outOfOrderFrames.add(frame);
        if (frame.isFinal()) {
            streamEndOffset = frame.getUpToOffset();
        }

        long previousContiguousUpToOffset = contiguousUpToOffset;
        while (!outOfOrderFrames.isEmpty() && outOfOrderFrames.first().getOffset() <= contiguousUpToOffset) {
            StreamElement nextFrame = outOfOrderFrames.pollFirst();
            if (nextFrame.getUpToOffset() > contiguousUpToOffset) {
                // First add frame and ...
                contiguousFrames.add(nextFrame);
                // ... then update the offset (otherwise: race condition)
                contiguousUpToOffset = nextFrame.getUpToOffset();
            }
        }
        return contiguousUpToOffset > previousContiguousUpToOffset;
    }
}
