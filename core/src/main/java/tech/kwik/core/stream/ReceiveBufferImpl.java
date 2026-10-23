/*
 * Copyright © 2023, 2024, 2025, 2026 Peter Doornbosch
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

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NavigableSet;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.stream.Collectors;

/**
 * A receive buffer implementation.
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
    // Estimated memory overhead (in bytes) of a buffered frame, i.e. memory used by a buffered frame on top of the
    // stream data it contains (the frame object, its byte array header, the collection node, etc.).
    static final int FRAME_OVERHEAD = 128;
    // Maximum memory a receive buffer may use, expressed as a multiple of the buffer size.
    static final int MAX_MEMORY_FACTOR = 2;

    private final NavigableSet<StreamElement> outOfOrderFrames = new ConcurrentSkipListSet<>();
    private final Queue<StreamElement> contiguousFrames = new ConcurrentLinkedQueue<>();
    private volatile long contiguousUpToOffset = 0;
    private volatile long readUpToOffset = 0;
    private volatile long streamEndOffset = -1;
    private volatile long bufferedOutOfOrderData;
    private volatile int outOfOrderFrameCount;
    // The number of contiguous frames is tracked by two counters, so that each counter has only one writer: the number
    // added is only updated by the add method (producer), the number removed only by the read method (consumer).
    private volatile long contiguousFramesAdded;
    private volatile long contiguousFramesRemoved;
    private final int maxCombinedFrameSize;
    private final long maxMemoryUsage;
    private volatile boolean discarded;
    private volatile long discardBeyondOffset = Long.MAX_VALUE;

    /**
     * Creates a receive buffer with the given buffer size.
     * @param bufferSize  the maximum amount of stream data that can be buffered at any time (as enforced by the caller,
     *                    e.g. by flow control); used to limit the memory the buffer may use.
     */
    public ReceiveBufferImpl(long bufferSize) {
        this(bufferSize, DEFAULT_MAX_COMBINED_FRAME_SIZE);
    }

    /**
     * Creates a receive buffer with the given buffer size and maximum combined frame size.
     * The maximum combined frame size must balance between the following two goals:
     * - the larger, the more bytes are copied when combining frames
     * - the smaller, the more memory overhead there will be for buffering out-of-order frames
     * Note that in normal circumstances, frames will usually not overlap (as this is inefficient use of network and
     * other resources). However, attackers could send overlapping frames in order to try to make the endpoint use more
     * memory than anticipated.
     * @param bufferSize  the maximum amount of stream data that can be buffered at any time (as enforced by the caller,
     *                    e.g. by flow control); used to limit the memory the buffer may use.
     * @param maxCombinedFrameSize  the maximum size of a combined frame (i.e. when frames are combined to remove
     *                              overlap, the resulting frame will not be larger than this size).
     */
    public ReceiveBufferImpl(long bufferSize, int maxCombinedFrameSize) {
        this.maxCombinedFrameSize = maxCombinedFrameSize;
        this.maxMemoryUsage = MAX_MEMORY_FACTOR * bufferSize;
    }

    @Override
    public long bytesAvailable() {
        // Cap at the discard offset (Long.MAX_VALUE when discardDataBeyond was not called) so that data beyond it,
        // which will never be returned by read(), is not reported as available. Clamp to 0, as discardDataBeyond may
        // run on another thread and lower the discard offset below readUpToOffset.
        return Long.max(0, Long.min(contiguousUpToOffset, discardBeyondOffset) - readUpToOffset);
    }

    @Override
    public boolean allRead() {
        return (streamEndOffset >= 0 && readUpToOffset == streamEndOffset)
                || readUpToOffset >= discardBeyondOffset;
    }

    @Override
    public int read(ByteBuffer buffer) {
        if (allRead()) {
            return -1;
        }

        int totalBytesRead = 0;
        StreamElement nextFrame = contiguousFrames.peek();
        while (nextFrame != null && buffer.hasRemaining()) {
            // Read the volatile discard offset once: discardDataBeyond may run on another thread and could otherwise
            // lower it below readUpToOffset between checks, which would make bytesToRead negative. When readUpToOffset
            // has already reached the discard offset there is nothing left to read (discardBeyondOffset is
            // Long.MAX_VALUE when discardDataBeyond was not called).
            long discardOffset = discardBeyondOffset;
            if (readUpToOffset >= discardOffset) {
                break;
            }
            // Never return data at or beyond the discard offset.
            long maxOffset = Long.min(discardOffset, nextFrame.getUpToOffset());
            int bytesToRead = (int) Long.min(buffer.remaining(), maxOffset - readUpToOffset);
            buffer.put(nextFrame.getStreamData(), (int) (readUpToOffset - nextFrame.getOffset()), bytesToRead);
            readUpToOffset += bytesToRead;
            totalBytesRead += bytesToRead;
            if (readUpToOffset == maxOffset) {
                contiguousFrames.poll();
                contiguousFramesRemoved++;
                nextFrame = contiguousFrames.peek();
            }
        }
        return totalBytesRead;
    }

    @Override
    public boolean allDataReceived() {
        return (streamEndOffset >= 0 && contiguousUpToOffset == streamEndOffset)
                || contiguousUpToOffset >= discardBeyondOffset;
    }

    @Override
    public long readOffset() {
        return readUpToOffset;
    }

    @Override
    public boolean add(StreamElement frame) {
        try {
            if (frame.isFinal()) {
                streamEndOffset = frame.getUpToOffset();
            }
            if (frame.getLength() == 0) {
                return false;
            }
            if (frame.getOffset() >= discardBeyondOffset) {
                // All data of this frame is at or beyond the discard offset, so it will never be read: drop it.
                return false;
            }

            long previousContiguousUpToOffset = contiguousUpToOffset;
            if (! addContiguous(frame)) {
                addOutOfOrder(frame);
            }

            while (!outOfOrderFrames.isEmpty() && outOfOrderFrames.first().getOffset() <= contiguousUpToOffset) {
                StreamElement nextFrame = outOfOrderFrames.pollFirst();
                outOfOrderFrameCount--;
                bufferedOutOfOrderData -= nextFrame.getLength();
                // Only frames that contain data that can still be read are moved to the contiguous frames, others are
                // dropped (which is the case when all data is before the contiguous offset or beyond the discard offset).
                if (Long.min(nextFrame.getUpToOffset(), discardBeyondOffset) > contiguousUpToOffset) {
                    if (nextFrame.getOffset() < contiguousUpToOffset) {
                        nextFrame = shrinkFrame(nextFrame, contiguousUpToOffset, nextFrame.getUpToOffset());
                    }
                    // First add frame and ...
                    contiguousFrames.add(nextFrame);
                    contiguousFramesAdded++;
                    // ... then update the offset (otherwise: race condition).
                    // The contiguous offset never advances beyond the discard offset, so that the status methods
                    // (e.g. bytesAvailable) do not account for data that will never be read.
                    contiguousUpToOffset = Long.min(nextFrame.getUpToOffset(), discardBeyondOffset);
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

    private boolean addContiguous(StreamElement frame) {
        if (frame.getOffset() == contiguousUpToOffset) {
            // Frame is exactly the next contiguous frame: add it to the contiguous queue and update the offset.
            contiguousFrames.add(frame);
            contiguousFramesAdded++;
            // The contiguous offset never advances beyond the discard offset, so that the status methods
            // (e.g. bytesAvailable) do not account for data that will never be read.
            contiguousUpToOffset = Long.min(frame.getUpToOffset(), discardBeyondOffset);
            return true;
        }
        else {
            return false;
        }
    }

    public long bufferedOutOfOrderData() {
        return bufferedOutOfOrderData;
    }

    /**
     * Returns an estimate of the memory used by this buffer: the buffered data plus an estimated overhead per frame.
     * @return  the estimated memory usage in bytes
     */
    long estimatedMemoryUsage() {
        long frameCount = contiguousFramesAdded - contiguousFramesRemoved + outOfOrderFrameCount;
        return bytesAvailable() + bufferedOutOfOrderData + frameCount * FRAME_OVERHEAD;
    }

    /**
     * Adds an out-of-order frame to the buffer, combining it with existing frames if they overlap (or are adjacent
     * while the buffer is fragmented, i.e. contains many small frames) and either the combined length does not exceed
     * the maximum combined frame size or one frame contains the other. Overlapping frames that cannot be combined are
     * shrunk to remove the overlap; adjacent frames that cannot be combined are left as they are.
     * @param frame  the frame to add
     */
    private void addOutOfOrder(StreamElement frame) {
        StreamElement before = outOfOrderFrames.lower(frame);
        StreamElement combinedWithBefore;
        if (before != null && (overlapping(before, frame) || (adjacent(before, frame) && fragmented(frame.getLength())))) {
            if (canCombine(before, frame)) {
                combinedWithBefore = combine(before, frame);
                outOfOrderFrames.remove(before);
                outOfOrderFrameCount--;
                bufferedOutOfOrderData -= before.getLength();
            }
            else if (adjacent(before, frame)) {
                // Adjacent (not overlapping) and too large to combine: nothing to do.
                combinedWithBefore = frame;
            }
            else {
                // Remove overlap by shrinking the new frame to start at the end of the "before" frame.
                combinedWithBefore = shrinkFrame(frame, before.getUpToOffset(), frame.getUpToOffset());
                // Special case: because the shrunk frame got a new (start) offset, it could now overlap with a different
                // "before", that was after the original "before".
                // For example: when adding 2502..3501 to 1000..3499, 3500..3500 (with max 2500),
                // after shrinking you get  3500..3501 and 3500..3500 becomes a new "before".
                if (outOfOrderFrames.lower(combinedWithBefore) != before) {
                    StreamElement newBefore = outOfOrderFrames.lower(combinedWithBefore);
                    combinedWithBefore = combine(newBefore, combinedWithBefore);
                    outOfOrderFrames.remove(newBefore);
                    outOfOrderFrameCount--;
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
            outOfOrderFrameCount++;
            bufferedOutOfOrderData += combinedWithAfter.getLength();
        }
    }

    StreamElement combineWithElementsAfter(StreamElement frameToAdd) {
        // To avoid copying the (growing) combined data for each frame that is combined, first collect the frames to
        // combine and only copy the data once at the end.
        List<StreamElement> framesToCombine = null;
        long startOffset = frameToAdd.getOffset();
        long upToOffset = frameToAdd.getUpToOffset();
        StreamElement after = outOfOrderFrames.higher(frameToAdd);
        while (after != null) {
            boolean overlapping = upToOffset > after.getOffset();
            boolean adjacent = upToOffset == after.getOffset();
            boolean heavilyFragmented = fragmented(upToOffset - startOffset);
            if (! (overlapping || (adjacent && heavilyFragmented))) {
                break;
            }
            if (canCombine(startOffset, upToOffset, after.getOffset(), after.getUpToOffset())) {
                if (framesToCombine == null) {
                    framesToCombine = new ArrayList<>();
                    framesToCombine.add(frameToAdd);
                }
                framesToCombine.add(after);
                upToOffset = Long.max(upToOffset, after.getUpToOffset());
                outOfOrderFrames.remove(after);
                outOfOrderFrameCount--;
                bufferedOutOfOrderData -= after.getLength();
                after = outOfOrderFrames.higher(after);
            }
            else {
                if (!adjacent) {
                    // Remove overlap by shrinking the new frame to end at the start of the "after" frame.
                    upToOffset = after.getOffset();
                }
                // Too large to combine; after shrinking, the combination with "after" would still be too large.
                break;
            }
        }
        if (framesToCombine == null) {
            return shrinkFrame(frameToAdd, startOffset, upToOffset);
        }
        else {
            return combine(framesToCombine, startOffset, upToOffset);
        }
    }

    /**
     * Returns whether the out-of-order frames are fragmented too much, i.e. there are many small frames.
     * @param inProgressLength  the length of the frame that is being added, which is not (yet) counted in the buffered
     *                          data and frame count
     */
    private boolean fragmented(long inProgressLength) {
        long data = bufferedOutOfOrderData + inProgressLength;
        return data < (outOfOrderFrameCount + 1) * 90L && data > 10 * 1024;
    }

    /**
     * Returns whether two overlapping or adjacent frames can be combined: either the combination does not exceed the maximum
     * combined frame size, or one of the frames contains the other, in which case the combination is just the
     * containing frame and combining does not lead to a larger frame.
     */
    private boolean canCombine(StreamElement frame1, StreamElement frame2) {
        return canCombine(frame1.getOffset(), frame1.getUpToOffset(), frame2.getOffset(), frame2.getUpToOffset());
    }

    private boolean canCombine(long offset1, long upToOffset1, long offset2, long upToOffset2) {
        return Long.max(upToOffset1, upToOffset2) - Long.min(offset1, offset2) <= maxCombinedFrameSize
                || (offset1 <= offset2 && upToOffset1 >= upToOffset2)
                || (offset2 <= offset1 && upToOffset2 >= upToOffset1);
    }

    static boolean overlapping(StreamElement frame1, StreamElement frame2) {
        assert frame1.getOffset() <= frame2.getOffset();
        return frame1.getUpToOffset() > frame2.getOffset();
    }

    static boolean adjacent(StreamElement frame1, StreamElement frame2) {
        assert frame1.getOffset() <= frame2.getOffset();
        return frame1.getUpToOffset() == frame2.getOffset();
    }

    static long combinedLength(StreamElement frame1, StreamElement frame2) {
        return Long.max(frame1.getUpToOffset(), frame2.getUpToOffset()) - Long.min(frame1.getOffset(), frame2.getOffset());
    }

    /**
     * Combines two overlapping or adjacent frames into one frame that covers both.
     * @param frame1  the frame with the lowest (or equal) offset
     * @param frame2  the frame that overlaps with or directly follows frame1
     */
    static StreamElement combine(StreamElement frame1, StreamElement frame2) {
        assert frame1.getOffset() <= frame2.getOffset();
        assert frame1.getUpToOffset() >= frame2.getOffset();

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

    /**
     * Combines a list of frames, ordered by offset and together covering the given range without gaps, into one frame
     * covering that range, copying the data only once. When one frame covers the whole range, no data is copied and
     * that frame is returned (or a shrunk copy of it, when it extends beyond the range).
     * @param frames  the frames to combine, ordered by offset; the first frame must start at startOffset and each frame
     *                must start at or before the end of the frames before it; except for the first, frames must not
     *                overlap
     * @param startOffset  the start offset of the combined frame, which must be equal to the offset of the first frame
     * @param upToOffset  the offset up to which (exclusive) the frames are combined; data beyond this offset is dropped
     * @return  a frame covering startOffset (inclusive) to upToOffset (exclusive)
     */
    static StreamElement combine(List<StreamElement> frames, long startOffset, long upToOffset) {
        assert !frames.isEmpty();
        assert frames.get(0).getOffset() == startOffset;

        // As frames are ordered by offset, only the frames starting at the start offset can contain all others.
        for (int i = 0; i < frames.size() && frames.get(i).getOffset() == startOffset; i++) {
            StreamElement frame = frames.get(i);
            if (frame.getUpToOffset() >= upToOffset) {
                // One frame contains all others: no need to copy.
                return shrinkFrame(frame, startOffset, upToOffset);
            }
        }

        byte[] combinedData = new byte[(int) (upToOffset - startOffset)];
        long filledUpToOffset = startOffset;
        for (StreamElement frame : frames) {
            assert frame.getOffset() <= filledUpToOffset;
            long copyUpToOffset = Long.min(frame.getUpToOffset(), upToOffset);
            if (copyUpToOffset > filledUpToOffset) {
                System.arraycopy(frame.getStreamData(), (int) (filledUpToOffset - frame.getOffset()),
                        combinedData, (int) (filledUpToOffset - startOffset), (int) (copyUpToOffset - filledUpToOffset));
                filledUpToOffset = copyUpToOffset;
            }
        }
        assert filledUpToOffset == upToOffset;
        // Final is a property of the stream end offset, so it only applies when the combined frame ends there. As no
        // frame contains all others, the last frame is the only frame that can end at the up-to offset.
        StreamElement lastFrame = frames.get(frames.size() - 1);
        boolean isFinal = lastFrame.isFinal() && lastFrame.getUpToOffset() == upToOffset;
        return new SimpleStreamElement(startOffset, combinedData, isFinal);
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
        return new SimpleStreamElement(newStartOffset, limitedData, frame.isFinal() && newUpToOffset == frame.getUpToOffset());
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
        // Discarding all data is equivalent to discarding everything from offset 0 onward: no data will ever be read
        // anymore.
        discardBeyondOffset = 0;
        // The discarded flag remains needed to make add() tolerate the races caused by clearing the buffers below while
        // another thread may be adding (see the catch block in add()).
        discarded = true;
        outOfOrderFrames.clear();
        outOfOrderFrameCount = 0;
        bufferedOutOfOrderData = 0;
        contiguousFrames.clear();
        contiguousFramesRemoved = contiguousFramesAdded;
    }

    @Override
    public void discardDataBeyond(long offset) {
        // This method may be called from any thread (not just the producer or consumer thread), so it must only touch
        // the volatile discardBeyondOffset and nothing else. In particular it must not write contiguousUpToOffset
        // (which is owned by the producer/add thread) nor modify the buffered frames (outOfOrderFrames,
        // contiguousFrames), as that would break the lock-free producer/consumer cooperation this class relies on (see
        // class javadoc). Instead, data beyond the offset is handled lazily: add() drops frames that fall entirely
        // beyond the offset, read() never returns data beyond it, and the status methods cap their result at it.
        // The offset can only decrease (a reset can only lower the reliable size, never raise it).
        discardBeyondOffset = Long.min(discardBeyondOffset, offset);
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

        @Override
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
