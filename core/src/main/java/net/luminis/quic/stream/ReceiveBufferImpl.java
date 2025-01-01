/*
 * Copyright © 2023, 2024, 2025 Peter Doornbosch
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
import java.util.Iterator;
import java.util.NavigableSet;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.stream.Collectors;

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

    private static final int DEFAULT_MAX_COMBINED_FRAME_SIZE = 5120;

    private final NavigableSet<StreamElement> outOfOrderFrames = new ConcurrentSkipListSet<>();
    private final Queue<StreamElement> contiguousFrames = new ConcurrentLinkedQueue<>();
    private volatile long contiguousUpToOffset = 0;
    private volatile long readUpToOffset = 0;
    private volatile long streamEndOffset = -1;
    private volatile long bufferedOutOfOrderData;
    private final int maxCombinedFrameSize;
    private volatile boolean discarded;

    public ReceiveBufferImpl() {
        this(DEFAULT_MAX_COMBINED_FRAME_SIZE);
    }

    /**
     * Creates a receive buffer with the given maximum combined frame size.
     * The maximum combined frame size must balance between the following two goals:
     * - the larger, the more bytes are copied when combining frames
     * - the smaller, the more memory overhead there will be for buffering out-of-order frames
     * Note that in normal circumstances, frames will usually not overlap (as this is inefficient use of network and
     * other resources). However, attackers could send overlapping frames in order to try to make the endpoint use more
     * memory than anticipated.
     * @param maxCombinedFrameSize  the maximum size of a combined frame (i.e. when frames are combined to remove
     *                              overlap, the resulting frame will not be larger than this size).
     */
    public ReceiveBufferImpl(int maxCombinedFrameSize) {
        this.maxCombinedFrameSize = maxCombinedFrameSize;
    }

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
        try {
            if (frame.getLength() > 0) {
                addWithoutOverlap(frame);
            }
            if (frame.isFinal()) {
                streamEndOffset = frame.getUpToOffset();
            }

            long previousContiguousUpToOffset = contiguousUpToOffset;
            while (!outOfOrderFrames.isEmpty() && outOfOrderFrames.first().getOffset() <= contiguousUpToOffset) {
                StreamElement nextFrame = outOfOrderFrames.pollFirst();
                if (nextFrame.getUpToOffset() > contiguousUpToOffset) {
                    if (nextFrame.getOffset() < contiguousUpToOffset) {
                        nextFrame = shrinkFrame(nextFrame, contiguousUpToOffset, nextFrame.getUpToOffset());
                    }
                    // First add frame and ...
                    contiguousFrames.add(nextFrame);
                    // ... then update the offset (otherwise: race condition)
                    contiguousUpToOffset = nextFrame.getUpToOffset();
                    bufferedOutOfOrderData -= nextFrame.getLength();
                }
            }
            return contiguousUpToOffset > previousContiguousUpToOffset;
        }
        catch (Exception e) {
            // Because the add method is the only method making modifications to the outOfOrderFrames, race conditions
            // will not occur. However, there is one exception: the discardAllData method. Concurrent call to this method
            // can cause a race condition, which can lead to various runtime exceptions in the code block wrapped by this
            // try-catch (e.g. NoSuchElementException, NullPointerException, etc.). Preventing them would require either
            // a lock or a lot of additional and ugly code, while not needed because when the discardAllData method has
            // been called, it doesn't matter whether the add method fails or not. It should just not throw an exception
            // in that case.
            if (discarded) {
                return false;
            }
            else {
                throw e;
            }
        }
    }

    public long bufferedOutOfOrderData() {
        return bufferedOutOfOrderData;
    }

    private void addWithoutOverlap(StreamElement frame) {
        StreamElement before = outOfOrderFrames.lower(frame);
        StreamElement combinedWithBefore;
        if (before != null && overlapping(before, frame)) {
            if (combinedLength(before, frame) <= maxCombinedFrameSize) {
                combinedWithBefore = combine(before, frame);
                outOfOrderFrames.remove(before);
                bufferedOutOfOrderData -= before.getLength();
            }
            else {
                combinedWithBefore = shrinkFrame(frame, before.getUpToOffset(), frame.getUpToOffset());
                // Special case: because the shrunk frame got a new (start) offset, it could now overlap with a different
                // "before", that was after the original "before".
                // For example: when adding 2502..3501 to 1000..3499, 3500..3500 (with max 2500),
                // after shrinking you get  3500..3501 and 3500..3500 becomes a new "before".
                if (outOfOrderFrames.lower(combinedWithBefore) != before) {
                    StreamElement newBefore = outOfOrderFrames.lower(combinedWithBefore);
                    combinedWithBefore = combine(newBefore, combinedWithBefore);
                    outOfOrderFrames.remove(newBefore);
                    bufferedOutOfOrderData -= newBefore.getLength();
                }
            }
        }
        else {
            combinedWithBefore = frame;
        }
        StreamElement combinedWithAfter = combineWithElementsAfter(combinedWithBefore);
        // In certain cases, the combined could exactly match an existing, so only count when really added.
        if (outOfOrderFrames.add(combinedWithAfter)) {
            bufferedOutOfOrderData += combinedWithAfter.getLength();
        }
    }

    StreamElement combineWithElementsAfter(StreamElement frameToAdd) {
        StreamElement after = outOfOrderFrames.higher(frameToAdd);
        while (after != null && overlapping(frameToAdd, after)) {
            StreamElement newCombined;
            if (combinedLength(frameToAdd, after) <= maxCombinedFrameSize) {
                newCombined = combine(frameToAdd, after);
                outOfOrderFrames.remove(after);
                bufferedOutOfOrderData -= after.getLength();
            }
            else {
                newCombined = shrinkFrame(frameToAdd, frameToAdd.getOffset(), after.getOffset());
            }
            after = outOfOrderFrames.higher(newCombined);
            frameToAdd = newCombined;
        }
        return frameToAdd;
    }

    static boolean overlapping(StreamElement frame1, StreamElement frame2) {
        assert frame1.getOffset() <= frame2.getOffset();
        return frame1.getUpToOffset() > frame2.getOffset();
    }

    static long combinedLength(StreamElement frame1, StreamElement frame2) {
        return Long.max(frame1.getUpToOffset(), frame2.getUpToOffset()) - Long.min(frame1.getOffset(), frame2.getOffset());
    }

    static StreamElement combine(StreamElement frame1, StreamElement frame2) {
        assert frame1.getOffset() <= frame2.getOffset();
        assert frame1.getUpToOffset() > frame2.getOffset();

        if (contains(frame1, frame2)) {
            return frame1;
        }
        if (contains(frame2, frame1)) {
            return frame2;
        }

        int overlap = (int) (frame1.getUpToOffset() - frame2.getOffset());
        int newLength = frame1.getLength() + frame2.getLength() - overlap;
        byte[] combinedData = new byte[newLength];
        System.arraycopy(frame1.getStreamData(), 0, combinedData, 0, frame1.getLength());
        System.arraycopy(
                frame2.getStreamData(),
                overlap,
                combinedData,
                frame1.getLength(),
                (int) (frame2.getLength() - overlap));

        return new SimpleStreamElement(frame1.getOffset(), combinedData, frame1.isFinal() || frame2.isFinal());
    }

    private static StreamElement shrinkFrame(StreamElement frame, long newStartOffset, long newUpToOffset) {
        assert newStartOffset >= frame.getOffset();
        assert newStartOffset <= frame.getUpToOffset();
        assert newUpToOffset <= frame.getUpToOffset();
        assert newUpToOffset >= frame.getOffset();

        int newLength = (int) (newUpToOffset - newStartOffset);
        if (newLength == frame.getLength()) {
            return frame;
        }
        byte[] limitedData = new byte[newLength];
        System.arraycopy(frame.getStreamData(), (int) (newStartOffset - frame.getOffset()), limitedData, 0, newLength);
        return new SimpleStreamElement(newStartOffset, limitedData, frame.isFinal());
    }


    static boolean contains(StreamElement containing, StreamElement contained) {
        return containing.getOffset() <= contained.getOffset()
                && containing.getUpToOffset() >= contained.getUpToOffset();
    }

    public String toDebugString() {
        return toDebugString(100);
    }

    public String toDebugString(int maxElements) {
        if (outOfOrderFrames.isEmpty()) {
            return "(none)";
        }
        else {
            return outOfOrderFrames.stream().limit(maxElements).map(Object::toString).collect(Collectors.joining(" "));
        }
    }

    // For testing only
    int checkOverlap() {
        return countOverlap(contiguousFrames.iterator()) + countOverlap(outOfOrderFrames.iterator());
    }

    int maxOutOfOrderFrameSize() {
        return outOfOrderFrames.stream().mapToInt(StreamElement::getLength).max().orElse(0);
    }

    int countOutOfOrderFrames() {
        return outOfOrderFrames.size();
    }

    private int countOverlap(Iterator<StreamElement> iterator) {
        int overlap = 0;
        if (iterator.hasNext()) {
            StreamElement current = iterator.next();
            while (iterator.hasNext()) {
                StreamElement next = iterator.next();
                if (current.getUpToOffset() > next.getOffset()) {
                    overlap = overlap + (int) (current.getUpToOffset() - next.getOffset());
                }
                current = next;
            }
        }
        return overlap;
    }

    public void discardAllData() {
        discarded = true;
        outOfOrderFrames.clear();
        bufferedOutOfOrderData = 0;
        contiguousFrames.clear();
    }

    private static class SimpleStreamElement implements StreamElement {
        private final long offset;
        private final byte[] data;
        private final boolean isFinal;

        public SimpleStreamElement(long offset, byte[] data, boolean isFinal) {
            this.offset = offset;
            this.data = data;
            this.isFinal = isFinal;
        }

        @Override
        public long getOffset() {
            return offset;
        }

        @Override
        public int getLength() {
            return data.length;
        }

        @Override
        public byte[] getStreamData() {
            return data;
        }

        @Override
        public long getUpToOffset() {
            return offset + data.length;
        }

        @Override
        public boolean isFinal() {
            return isFinal;
        }

        public int compareTo(StreamElement other) {
            if (this.offset != other.getOffset()) {
                return Long.compare(this.offset, other.getOffset());
            }
            else {
                return Integer.compare(this.data.length, other.getLength());
            }
        }

        @Override
        public String toString() {
            return "" + offset + ".." + (offset + data.length - 1);
        }
    }
}
