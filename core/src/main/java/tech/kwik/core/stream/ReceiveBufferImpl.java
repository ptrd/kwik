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

import tech.kwik.core.impl.TransportError;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NavigableSet;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import static tech.kwik.core.QuicConstants.TransportErrorCode.INTERNAL_ERROR;

/**
 * A receive buffer implementation.
 * <p>
 * This implementation is not thread-safe, but concurrent access by separate producer and consumer threads is supported,
 * under the condition that the add method is never called concurrently and the collection of read methods (i.e. all
 * other methods) are never called concurrently.
 * These conditions are met in the practical case that:
 * <ul>
 *   <li>there is only one producer thread and only one consumer thread</li>
 *   <li>the producer thread only calls the add method</li>
 *   <li>the consumer thread never calls the add method</li>
 * </ul>
 * <p>
 * Memory usage is limited to {@link #MAX_MEMORY_FACTOR} times the buffer size; when the estimated memory usage
 * (buffered data plus {@link #FRAME_OVERHEAD} per buffered frame) exceeds this limit, {@link #add(StreamElement)}
 * throws an INTERNAL_ERROR transport error. Example scenarios, with a buffer size of 250_000 (the default max stream
 * data), so a limit of 500_000 bytes, and nothing read by the application (unless stated otherwise):
 * <p>
 * Scenarios that lead to too much memory overhead:
 * <ul>
 *   <li>out-of-order frames of 1 byte with 1 byte gaps (offsets 1, 3, 5, ...): error after about 5150 frames, i.e. at
 *   offset 10_000 (each frame costs 1 + 96 bytes)</li>
 *   <li>out-of-order frames of 20 bytes with 1 byte gaps: error after about 4300 frames (offset 90_000)</li>
 *   <li>out-of-order frames of 50 bytes with 10 byte gaps: error after about 3400 frames (offset 205_000)</li>
 *   <li>out-of-order frames of 90 bytes with 1 byte gaps: error after about 2700 frames (offset 245_000)</li>
 * </ul>
 * In general: out-of-order frames that cannot be combined because of the gaps in between, and that are smaller than
 * about {@link #FRAME_OVERHEAD} bytes, can exceed the limit before the buffer is full.
 * <p>
 * Scenarios that do not lead to too much memory overhead:
 * <ul>
 *   <li>in-order frames of any size that are read by the application while they arrive: usage stays (close to) 0</li>
 *   <li>in-order frames of 1 byte (or 10 bytes), never read: about 1.55 times the buffer size, as small contiguous
 *   frames are compacted into chunks when the overhead is high</li>
 *   <li>in-order frames of 1200 bytes (typical for full packets): about 1.1 times the buffer size</li>
 *   <li>out-of-order frames of 1200 bytes, with every other frame lost: about 0.5 times the buffer size</li>
 *   <li>out-of-order adjacent small frames (e.g. 1, 10 or 100 bytes, offsets starting at 1): about 1.5 times the
 *   buffer size, as adjacent small out-of-order frames are combined when the overhead is high; larger adjacent frames
 *   (see {@link #COMPACTION_THRESHOLD}) are not combined, as their overhead is at most 25% of the data they contain</li>
 *   <li>out-of-order frames of 95 or 100 bytes with 1 byte gaps: about 1.99 and 1.94 times the buffer size (just
 *   within the limit)</li>
 *   <li>out-of-order frames of 200 bytes with 200 byte gaps: about 0.75 times the buffer size</li>
 *   <li>out-of-order frames of 10 bytes with 100 byte gaps: about 0.95 times the buffer size (the gaps limit the
 *   number of frames)</li>
 *   <li>in-order frames of 1 byte up to half of the buffer, followed by out-of-order frames of 200 bytes with 1 byte
 *   gaps: about 1.75 times the buffer size</li>
 *   <li>overlapping frames (e.g. 1200 byte frames retransmitted with shifted boundaries, followed by 1 byte frames
 *   within the already received data): about 1.1 times the buffer size, as overlap is removed and frames are
 *   combined</li>
 * </ul>
 */
public class ReceiveBufferImpl implements ReceiveBuffer {

    private static final int DEFAULT_MAX_COMBINED_FRAME_SIZE = 5120;
    /**
     * Estimated memory overhead (in bytes) of a buffered frame, i.e. memory used by a buffered frame on top of the
     * stream data it contains. With a 64-bit JVM using compressed oops and compressed class pointers (the default for
     * heaps smaller than 32 GB: 12 byte object header, 4 byte references, 8 byte object alignment), the overhead is:
     * - the frame object: 32 bytes (both StreamFrame and SimpleStreamElement / ChunkStreamElement)
     * - the byte array holding the data: 16 bytes header plus 0 to 7 bytes of alignment padding
     * - for a frame in outOfOrderFrames: the ConcurrentSkipListSet is backed by a ConcurrentSkipListMap, which uses a
     *   24 byte Node per element (the value is the shared Boolean.TRUE) plus on average 0.5 Index object of 24 bytes
     *   (an element gets an index with probability 1/4, each additional level with probability 1/2), so 36 bytes
     * - for a frame in contiguousFrames: the ConcurrentLinkedQueue uses a 24 byte Node per element
     * Total: about 88 bytes for an out-of-order frame and about 76 bytes for a contiguous frame (measured with JOL:
     * 87 and 75), with a maximum of about 91 bytes when padding is maximal. The estimate is an upper bound for this
     * (default) case, and also for compact object headers (-XX:+UseCompactObjectHeaders), where the overhead is lower
     * (about 79 and 59 bytes). Without compressed oops (e.g. heap larger than 32 GB) references are 8 bytes, resulting
     * in about 121 and 91 bytes, so in that case the estimate is too low for out-of-order frames.
     */
    static final int FRAME_OVERHEAD = 96;
    /**
     * Contiguous frames smaller than this size are compacted into chunks when the overhead is high. For larger frames,
     * the overhead is at most 25% of the data they contain, so even when all buffered data is in such frames, the
     * overhead stays well within the budget; copying their data would cost more than it would gain.
     */
    static final int COMPACTION_THRESHOLD = 4 * FRAME_OVERHEAD;
    /**
     * Capacity of the chunks that small contiguous frames are compacted into. A chunk must be filled completely before
     * another frame can be added after it, so frames that follow a partly filled chunk are (partly) copied into it, even
     * when they are large: the smaller the chunk, the less data is copied. On the other hand, the chunk must be large
     * compared to the frames that are compacted, for compaction to substantially reduce the overhead (which is at most
     * 1/16 of the data for a chunk of this size).
     */
    static final int CHUNK_SIZE = 4 * COMPACTION_THRESHOLD;
    // Maximum memory a receive buffer may use, expressed as a multiple of the buffer size.
    static final int MAX_MEMORY_FACTOR = 2;

    private final NavigableSet<StreamElement> outOfOrderFrames = new ConcurrentSkipListSet<>();
    private final Queue<StreamElement> contiguousFrames = new ConcurrentLinkedQueue<>();
    // The last contiguous frame, when it is a chunk that is not yet completely filled; only accessed by the producer
    // (except for estimating memory usage).
    private volatile ChunkStreamElement openChunk;
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
    private final long maxOverhead;
    private final int chunkCapacity;
    private volatile boolean discarded;
    private volatile long discardBeyondOffset = Long.MAX_VALUE;
    private final ConnectionMemoryBudget connectionMemoryBudget;
    // The overhead that is reported to the connection memory budget, i.e. this buffer's share in the connection overhead.
    private final AtomicLong reportedOverhead = new AtomicLong();

    /**
     * Creates a receive buffer with the given buffer size.
     * @param bufferSize  the maximum amount of stream data that can be buffered at any time (as enforced by the caller,
     *                    e.g. by flow control); used to limit the memory the buffer may use.
     */
    public ReceiveBufferImpl(long bufferSize) {
        this(bufferSize, null);
    }

    /**
     * Creates a receive buffer with the given buffer size, that shares the given memory budget with the other receive
     * buffers of the connection.
     * @param bufferSize  the maximum amount of stream data that can be buffered at any time (as enforced by the caller,
     *                    e.g. by flow control); used to limit the memory the buffer may use.
     * @param connectionMemoryBudget  the memory budget of the connection, or null if there is no connection limit
     */
    public ReceiveBufferImpl(long bufferSize, ConnectionMemoryBudget connectionMemoryBudget) {
        this(bufferSize, DEFAULT_MAX_COMBINED_FRAME_SIZE, connectionMemoryBudget);
    }

    ReceiveBufferImpl(long bufferSize, int maxCombinedFrameSize) {
        this(bufferSize, maxCombinedFrameSize, null);
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
     * @param connectionMemoryBudget  the memory budget of the connection, or null if there is no connection limit
     */
    public ReceiveBufferImpl(long bufferSize, int maxCombinedFrameSize, ConnectionMemoryBudget connectionMemoryBudget) {
        this.maxCombinedFrameSize = maxCombinedFrameSize;
        this.connectionMemoryBudget = connectionMemoryBudget;
        this.maxMemoryUsage = MAX_MEMORY_FACTOR * bufferSize;
        // As the amount of buffered data never exceeds the buffer size, the remainder is available for overhead.
        this.maxOverhead = maxMemoryUsage - bufferSize;
        // Chunks must be small enough for the unused capacity of a chunk to stay well within the overhead budget.
        this.chunkCapacity = (int) Long.max(1, Long.min(CHUNK_SIZE, maxOverhead / 4));
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
            // When end of stream becomes known after all data was read (e.g. an empty final frame), a partly filled
            // chunk might still be present, as it is only removed when it is read up to its end or end of stream.
            purgeAllData();
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
            // Never return data at or beyond the discard offset, nor beyond the contiguous offset, as the frame can be a
            // chunk that is only partly filled (the contiguous offset is updated after the data is written to the chunk,
            // so reading it first guarantees that the data up to it is visible).
            long maxOffset = min(discardOffset, contiguousUpToOffset, nextFrame.getUpToOffset());
            if (maxOffset <= readUpToOffset) {
                // Only possible when the frame is a partly filled chunk of which all data that is filled has been read.
                break;
            }
            int bytesToRead = (int) min(buffer.remaining(), maxOffset - readUpToOffset);
            buffer.put(nextFrame.getStreamData(), (int) (readUpToOffset - nextFrame.getOffset()), bytesToRead);
            readUpToOffset += bytesToRead;
            totalBytesRead += bytesToRead;
            // Only remove the frame when it is read up to its end; for a chunk this means that it has been filled
            // completely, or end of stream is reached, so that the producer will not add data to it anymore.
            if (readUpToOffset == nextFrame.getUpToOffset()) {
                contiguousFrames.poll();
                contiguousFramesRemoved++;
                nextFrame = contiguousFrames.peek();
            }
            if (readUpToOffset == streamEndOffset) {
                purgeAllData();
                break;
            }
        }

        if (readUpToOffset >= discardBeyondOffset) {
            purgeAllData();
        }

        if (totalBytesRead > 0) {
            reportOverhead();
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
    public boolean add(StreamElement frame) throws TransportError {
        try {
            // Read the volatile discard offset once, as discardAllData or discardDataBeyond may run on another thread:
            // when lowered between the checks below, the frame could be shrunk to end before its start.
            long discardOffset = discardBeyondOffset;
            if (discardOffset != Long.MAX_VALUE) {
                dropOutOfOrderFramesBeyondDiscardOffset();
            }

            if (frame.isFinal()) {
                streamEndOffset = frame.getUpToOffset();
                if (readUpToOffset == streamEndOffset) {
                    // All data data read already
                    purgeAllData();
                }
            }
            if (frame.getLength() == 0) {
                return false;
            }
            if (frame.getOffset() >= discardOffset) {
                // All data of this frame is at or beyond the discard offset, so it will never be read: drop it.
                return false;
            }
            if (frame.getUpToOffset() >= discardOffset) {
                frame = shrinkFrame(frame, frame.getOffset(), discardOffset);
            }

            long previousContiguousUpToOffset = contiguousUpToOffset;
            // Add frame directly to contiguous collection if it is contiguous, add to out of order collection otherwise.
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
                    // Moving a frame does not change the overhead, so compacting it would not help to stay within the
                    // limit, while its data is likely to be read soon.
                    appendContiguous(nextFrame, false);
                }
            }
            if (discarded) {
                // All data may have been purged concurrently (by read or discardAllData), after which this method could
                // have added data to the (just cleared) buffers; as no data will ever be read anymore, release it.
                purgeAllData();
                return false;
            }
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-21.7
            // "QUIC deployments SHOULD provide mitigations for stream fragmentation attacks. Mitigations could consist of
            //  (...) limiting the size of tracking data structures, (...)"
            // As contiguous frames are compacted when the overhead is high, this limit can only be exceeded by out-of-order
            // frames that cannot be combined (e.g. small frames with gaps in between).
            reportOverhead();
            if (estimatedMemoryUsage() > maxMemoryUsage) {
                throw new TransportError(INTERNAL_ERROR, "excessive memory use by stream data fragmentation");
            }
            if (connectionMemoryBudget != null && connectionMemoryBudget.isExceeded()) {
                throw new TransportError(INTERNAL_ERROR, "excessive memory use by stream data fragmentation on connection");
            }
            return contiguousUpToOffset > previousContiguousUpToOffset;
        }
        catch (Exception e) {
            // Because the add method is the only method making modifications to the outOfOrderFrames, race conditions
            // will not occur. However, there is one exception: the purgeAllData method (called by read and
            // discardAllData). Concurrent call to this method can cause a race condition, which can lead to various
            // runtime exceptions in the code block wrapped by this try-catch (e.g. NoSuchElementException,
            // NullPointerException, etc.). Preventing them would require either a lock or a lot of additional and ugly
            // code, while not needed because when the purgeAllData method has been called, it doesn't matter whether
            // the add method fails or not. It should just not throw an exception in that case.
            if (discarded) {
                purgeAllData();
                return false;
            }
            else {
                throw e;
            }
        }
    }

    /**
     * Adds a frame to the contiguous frames collection if it matches exactly with the data that is present in it
     * (no gap, no overlap).
     * @param frame  the frame to add
     * @return       whether the frame is actually added
     */
    private boolean addContiguous(StreamElement frame) {
        if (frame.getOffset() == contiguousUpToOffset) {
            // Frame is exactly the next contiguous frame: add it to the contiguous queue and update the offset.
            appendContiguous(frame, true);
            return true;
        }
        else {
            return false;
        }
    }

    /**
     * Appends a frame that starts exactly at the contiguous offset to the contiguous frames and updates the contiguous
     * offset. When the overhead is high, small frames (see {@link #COMPACTION_THRESHOLD}) are not added as separate
     * frames, but their data is copied into a chunk, to limit the memory overhead of many small frames.
     * @param frame  the frame to append, which must start at the contiguous offset
     * @param allowCompaction  whether a new chunk may be started for the frame (when overhead is high); an open chunk is
     *                         always filled first, regardless of this flag, as no frame can be added after it before it
     *                         is full
     */
    private void appendContiguous(StreamElement frame, boolean allowCompaction) {
        assert frame.getOffset() == contiguousUpToOffset;
        int bytesConsumedFromFrame = 0;
        if (openChunk != null) {
            // A chunk must be filled completely before any other frame is added after it, because the reader only
            // moves on to the next frame when it has read the chunk up to its (fixed) end.
            bytesConsumedFromFrame = openChunk.append(frame, 0);
            if (openChunk.isFull()) {
                openChunk = null;
            }
        }
        int remainingBytesInFrame = frame.getLength() - bytesConsumedFromFrame;
        if (remainingBytesInFrame > 0) {
            if (allowCompaction && remainingBytesInFrame < Integer.min(chunkCapacity, COMPACTION_THRESHOLD)
                    && overheadIsHigh()) {
                ChunkStreamElement chunk = new ChunkStreamElement(frame.getOffset() + bytesConsumedFromFrame, chunkCapacity);
                int appended = chunk.append(frame, bytesConsumedFromFrame);
                assert appended == remainingBytesInFrame;
                contiguousFrames.add(chunk);
                contiguousFramesAdded++;
                openChunk = chunk;
            }
            else {
                // compaction not allowed, overhead is not high or remaining is not small: add the (shrunk) frame
                contiguousFrames.add(bytesConsumedFromFrame == 0?
                        frame:
                        shrinkFrame(frame, frame.getOffset() + bytesConsumedFromFrame, frame.getUpToOffset()));
                contiguousFramesAdded++;
            }
        }
        // Only update the offset after the frame (or its data) has been added (otherwise: race condition).
        // The contiguous offset never advances beyond the discard offset, so that the status methods
        // (e.g. bytesAvailable) do not account for data that will never be read.
        contiguousUpToOffset = Long.min(frame.getUpToOffset(), discardBeyondOffset);
    }

    /**
     * Removes the out-of-order frames that start at or beyond the discard offset, as their data will never be read.
     * Must only be called by the producer (as it modifies the out-of-order frames).
     */
    private void dropOutOfOrderFramesBeyondDiscardOffset() {
        long discardOffset = discardBeyondOffset;
        boolean dropped = false;
        while (!outOfOrderFrames.isEmpty() && outOfOrderFrames.last().getOffset() >= discardOffset) {
            StreamElement droppedFrame = outOfOrderFrames.pollLast();
            outOfOrderFrameCount--;
            bufferedOutOfOrderData -= droppedFrame.getLength();
            dropped = true;
        }
        if (dropped) {
            // Report here, as add might return (without reporting) before it adds anything.
            reportOverhead();
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
        return bytesAvailable() + bufferedOutOfOrderData + estimatedOverhead();
    }

    /**
     * Returns an estimate of the memory used by this buffer on top of the buffered data: the estimated overhead per
     * frame and the unused capacity of a chunk.
     * @return  the estimated overhead in bytes
     */
    long estimatedOverhead() {
        long frameCount = contiguousFramesAdded - contiguousFramesRemoved + outOfOrderFrameCount;
        ChunkStreamElement chunk = openChunk;
        long unusedChunkCapacity = chunk != null? chunk.freeSpace(): 0;
        return frameCount * FRAME_OVERHEAD + unusedChunkCapacity;
    }

    /**
     * Returns whether the overhead is so high that new (small) contiguous frames are compacted into chunks and adjacent
     * out-of-order frames are combined.
     * Compacting starts at half the overhead budget, so that the overhead of the frames buffered before compacting
     * started, plus the overhead of the chunks, stays within the budget.
     * The same holds for the connection memory budget: without compacting when the overhead of all buffers together
     * is high, in-order traffic with small frames on many streams would exceed the connection budget before any of
     * the buffers would start compacting.
     */
    boolean overheadIsHigh() {
        return estimatedOverhead() > maxOverhead / 2
                || connectionMemoryBudget != null && connectionMemoryBudget.overheadIsHigh();
    }

    /**
     * Adds an out-of-order frame to the buffer, combining it with existing frames if they overlap (or are adjacent and
     * both small, while the overhead is high, i.e. there are many small frames) and either the combined length does not
     * exceed the maximum combined frame size or one frame contains the other. Overlapping frames that cannot be combined
     * are shrunk to remove the overlap; adjacent frames that cannot be combined are left as they are.
     * @param frame  the frame to add
     */
    private void addOutOfOrder(StreamElement frame) {
        // Use floor, so that an existing frame equal to the new frame is found as "before" (and combined with it);
        // otherwise, if the new frame is combined with frames after it, the existing frame would remain.
        StreamElement before = outOfOrderFrames.floor(frame);
        // The frame before the new frame to combine it with (if any); the actual combining is done together with
        // combining the frames after, so that the data is copied only once.
        StreamElement combineWithBefore = null;
        if (before != null && (overlapping(before, frame)
                || (adjacent(before, frame) && bothSmall(before.getLength(), frame.getLength()) && overheadIsHigh()))) {
            if (canCombine(before, frame)) {
                combineWithBefore = before;
            }
            else if (adjacent(before, frame)) {
                // Adjacent (not overlapping) and too large to combine: nothing to do.
            }
            else {
                // Remove overlap by shrinking the new frame to start at the end of the "before" frame.
                frame = shrinkFrame(frame, before.getUpToOffset(), frame.getUpToOffset());
                // Special case: because the shrunk frame got a new (start) offset, it could now overlap with a different
                // "before", that was after the original "before".
                // For example: when adding 2502..3501 to 1000..3499, 3500..3500 (with max 2500),
                // after shrinking you get  3500..3501 and 3500..3500 becomes a new "before".
                // As out-of-order frames do not overlap, such a new "before" must start exactly at the end of the
                // original "before", i.e. at the same offset as the shrunk frame, and be shorter (otherwise it would
                // not be lower). Hence, it is contained in the shrunk frame, so the two can always be combined.
                StreamElement newBefore = outOfOrderFrames.lower(frame);
                if (newBefore != before) {
                    combineWithBefore = newBefore;
                }
            }
        }
        StreamElement combinedWithAfter = combineWithNeighbours(combineWithBefore, frame);
        // In certain cases, the combined could exactly match an existing, so only count when really added.
        if (outOfOrderFrames.add(combinedWithAfter)) {
            outOfOrderFrameCount++;
            bufferedOutOfOrderData += combinedWithAfter.getLength();
        }
    }

    /**
     * Combines the frame to add with the given frame before it (if not null) and with the frames after it that it
     * overlaps (or is adjacent to, when they are small and the overhead is high). The frames it is combined with are
     * removed from the out-of-order frames; the combined frame is not added.
     * @param before  the (out-of-order) frame before the frame to add, that must be combined with it, or null
     * @param frameToAdd  the frame to add
     * @return  the combined frame
     */
    StreamElement combineWithNeighbours(StreamElement before, StreamElement frameToAdd) {
        // To avoid copying the (growing) combined data for each frame that is combined, first collect the frames to
        // combine and only copy the data once at the end.
        List<StreamElement> framesToCombine = null;
        long startOffset = frameToAdd.getOffset();
        long upToOffset = frameToAdd.getUpToOffset();
        if (before != null) {
            // Before must start at or before the frame to add and overlap or be adjacent to it.
            assert before.getOffset() <= frameToAdd.getOffset() && before.getUpToOffset() >= frameToAdd.getOffset();
            outOfOrderFrames.remove(before);
            outOfOrderFrameCount--;
            bufferedOutOfOrderData -= before.getLength();
            framesToCombine = new ArrayList<>();
            framesToCombine.add(before);
            framesToCombine.add(frameToAdd);
            startOffset = before.getOffset();
            upToOffset = Long.max(before.getUpToOffset(), upToOffset);
        }
        StreamElement after = outOfOrderFrames.higher(frameToAdd);
        while (after != null) {
            boolean overlapping = upToOffset > after.getOffset();
            boolean adjacent = upToOffset == after.getOffset();
            // Evaluated in each iteration, as combining frames decreases the overhead.
            if (! (overlapping || (adjacent && bothSmall(upToOffset - startOffset, after.getLength()) && overheadIsHigh()))) {
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

    /**
     * Returns whether two adjacent frames with the given lengths are both small enough (see
     * {@link #COMPACTION_THRESHOLD}) to be combined. Larger frames are not combined, as their overhead is small enough
     * and copying their data would cost more than it would gain. This also limits the amount of data copied when a
     * combined frame grows by repeatedly combining it with small adjacent frames.
     */
    static boolean bothSmall(long length1, long length2) {
        return length1 < COMPACTION_THRESHOLD && length2 < COMPACTION_THRESHOLD;
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
                (frame2.getLength() - overlap));

        return new SimpleStreamElement(frame1.getOffset(), combinedData);
    }

    static long min(long l1, long l2) {
        return Long.min(l1, l2);
    }

    static long min(long l1, long l2, long l3) {
        return Long.min(Long.min(l1, l2), l3);
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
        return new SimpleStreamElement(startOffset, combinedData);
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
        return new SimpleStreamElement(newStartOffset, limitedData);
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

    // region For testing only!
    int checkOverlap() {
        return countOverlap(contiguousFrames.iterator()) + countOverlap(outOfOrderFrames.iterator());
    }

    int maxOutOfOrderFrameSize() {
        return outOfOrderFrames.stream().mapToInt(StreamElement::getLength).max().orElse(0);
    }

    // Only for testing! Don't use for production code, size() is O(n)!
    int countOutOfOrderFrames() {
        return outOfOrderFrames.size();
    }

    // Only for testing! Don't use for production code, size() is O(n)!
    int countContiguousFrames() {
        return contiguousFrames.size();
    }
    // endregion

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
        purgeAllData();
    }

    /**
     * Reports the change in overhead (since the last report) to the connection memory budget. As this method can be
     * called concurrently by the producer and the consumer, the reported overhead is updated atomically, such that the
     * total reported to the connection memory budget always equals the last value of the reported overhead.
     * When all data is purged, the overhead is zero; the discarded flag is used for this instead of the frame counts, as
     * these can be (temporarily) incorrect when purging runs concurrently with the consumer.
     */
    private void reportOverhead() {
        if (connectionMemoryBudget != null) {
            long currentOverhead = discarded? 0: estimatedOverhead();
            long previousOverhead = reportedOverhead.getAndSet(currentOverhead);
            connectionMemoryBudget.update(currentOverhead - previousOverhead);
            if (discarded) {
                // All data was purged concurrently (after which the purge reported zero), so the overhead reported
                // above may be outdated: report zero again.
                connectionMemoryBudget.update(-reportedOverhead.getAndSet(0));
            }
        }
    }

    @Override
    public void discardDataBeyond(long offset) {
        // This method may be called from any thread (not just the producer or consumer thread), so it must not write
        // contiguousUpToOffset (which is owned by the producer/add thread) nor modify the buffered frames
        // (outOfOrderFrames, contiguousFrames), as that would break the lock-free producer/consumer cooperation this
        // class relies on (see class javadoc). Instead, data beyond the offset is handled lazily: add() drops frames
        // that fall entirely beyond the offset (both new and buffered out-of-order frames), read() never returns data
        // beyond it, and the status methods cap their result at it.
        // The offset can only decrease (a reset can only lower the reliable size, never raise it).
        discardBeyondOffset = Long.min(discardBeyondOffset, offset);
        // The only exception is when everything up to the offset has already been read: as no data will ever be read
        // anymore, all data is purged, just like discardAllData does (purgeAllData can run concurrently with add).
        // When read runs concurrently, at least one of both purges, as both write their own offset before reading the
        // other's.
        if (readUpToOffset >= discardBeyondOffset) {
            purgeAllData();
        }
    }

    private void purgeAllData() {
        // Only called when no data will ever be read anymore. As this method can run concurrently with add (when called
        // by read or discardAllData), it first sets the discarded flag, which makes add() tolerate the races caused by
        // clearing the buffers below (see the catch block in add()).
        discarded = true;
        outOfOrderFrames.clear();
        outOfOrderFrameCount = 0;
        bufferedOutOfOrderData = 0;
        contiguousFrames.clear();
        contiguousFramesRemoved = contiguousFramesAdded;  // atomic operation, added - removed can never be negative
        openChunk = null;
        reportOverhead();
    }

    private static class SimpleStreamElement implements StreamElement {
        protected final long offset;
        protected final byte[] data;

        public SimpleStreamElement(long offset, byte[] data) {
            this.offset = offset;
            this.data = data;
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
            throw new UnsupportedOperationException("isFinal() is not supported on SimpleStreamElement");
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

    /**
     * A contiguous frame with a fixed capacity, that is filled with data from (small) frames. The data up to the
     * contiguous offset can be read, while the producer is still adding data to it.
     */
    private static class ChunkStreamElement extends SimpleStreamElement {
        private int filled;

        public ChunkStreamElement(long offset, int capacity) {
            super(offset, new byte[capacity]);
        }

        /**
         * Copies as much data from the given frame as fits into this chunk.
         * @param frame  the frame to copy data from
         * @param fromIndex  the index in the frame data (not offset!) to start copying from; the stream offset of this
         *                   data must be equal to the offset up to which this chunk is filled
         * @return  the number of bytes copied
         */
        int append(StreamElement frame, int fromIndex) {
            assert fromIndex < frame.getLength();
            // Check stream offset of first byte to copy matches
            assert frame.getOffset() + fromIndex == offset + filled;
            int count = Integer.min(freeSpace(), frame.getLength() - fromIndex);
            System.arraycopy(frame.getStreamData(), fromIndex, data, filled, count);
            filled += count;
            return count;
        }

        int freeSpace() {
            return data.length - filled;
        }

        boolean isFull() {
            return filled == data.length;
        }

        @Override
        public String toString() {
            return "" + offset + ".." + (offset + filled - 1 + " (+" + freeSpace() + ")");
        }
    }
}
