/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.frame;

import tech.kwik.core.QuicConstants;
import tech.kwik.core.generic.IntegerTooLargeException;
import tech.kwik.core.generic.InvalidIntegerEncodingException;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
 */
public class AckFrame extends QuicFrame {

    public static final int FIXED_SENDER_ACK_DELAY_EXPONENT = 3;

    private static final int FIXED_SENDER_ACK_DELAY_SCALE = (int) Math.pow(2, FIXED_SENDER_ACK_DELAY_EXPONENT);
    private static final int MAX_FRAME_SIZE = 1000;  // Should be large enough; leave some space for packet overhead.

    private byte[] frameBytes;
    private long largestAcknowledged;
    private int ackDelay;
    private List<Range> acknowledgedRanges;
    // https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    // "...  a default value of 3 is assumed (indicating a multiplier of 8)."
    private int delayScale = 8;
    private String stringRepresentation = null;

    public AckFrame() {
    }

    public AckFrame(long packetNumber) {
        this(Version.getDefault(), List.of(new Range(packetNumber)), 0);
    }

    public AckFrame(Range ackRange) {
        this(Version.getDefault(), List.of(ackRange), 0);
    }

    public AckFrame(List<Range> ackRanges) {
        this(Version.getDefault(), ackRanges, 0);
    }

    /**
     * Creates an AckFrame given a (sorted, non-adjacent) list of ranges and an ack delay.
     * @param quicVersion
     * @param ackRanges
     * @param ackDelayInMillis   the ack delay in milliseconds
     */
    public AckFrame(Version quicVersion, List<Range> ackRanges, int ackDelayInMillis) {
        if (! Range.validRangeList(ackRanges)) {
            throw new IllegalArgumentException("invalid range");  // TODO: replace by assert?
        }

        acknowledgedRanges = List.copyOf(ackRanges);
        this.delayScale = FIXED_SENDER_ACK_DELAY_SCALE;
        this.ackDelay = ackDelayInMillis * 1000 / delayScale;   // In an ack frame, the delay is in _microseconds_!

        Iterator<Range> rangeIterator = ackRanges.iterator();
        Range firstRange = rangeIterator.next();
        largestAcknowledged = firstRange.getLargest();

        ByteBuffer buffer = ByteBuffer.allocate(MAX_FRAME_SIZE);
        buffer.put((byte) 0x02);
        VariableLengthInteger.encode(largestAcknowledged, buffer);
        VariableLengthInteger.encode(ackDelay, buffer);
        int ackRangeCountFieldPosition = buffer.position();
        int ackRangeCountFieldLength = VariableLengthInteger.encode(ackRanges.size() - 1, buffer);
        VariableLengthInteger.encode(firstRange.size() - 1, buffer);

        long smallest = firstRange.getSmallest();
        int rangesAdded = 0;
        while (rangeIterator.hasNext()) {
            Range next = rangeIterator.next();
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
            // "Gap: A variable-length integer indicating the number of contiguous unacknowledged packets preceding the
            //  packet number one lower than the smallest in the preceding ACK Range."
            int gap = (int) (smallest - next.getLargest() - 2);  // e.g. 9..9, 5..4 => un-acked: 8, 7, 6; gap: 2
            // "ACK Range Length: A variable-length integer indicating the number of contiguous acknowledged packets
            //  preceding the largest packet number, as determined by the preceding Gap."
            int ackRangeLength = next.size() - 1;
            VariableLengthInteger.encode(gap, buffer);
            VariableLengthInteger.encode(ackRangeLength, buffer);
            rangesAdded++;

            smallest = next.getSmallest();

            if (buffer.limit() - buffer.position() < 2 * 8) {
                // Not enough space left for the next range, so we stop here.
                break;
            }
        }

        if (rangesAdded < acknowledgedRanges.size() - 1) {
            // Correct ACK Range Count field, because we did not serialize all ranges.
            int lastPosition = buffer.position();
            buffer.position(ackRangeCountFieldPosition);
            VariableLengthInteger.encode(rangesAdded, buffer, ackRangeCountFieldLength);
            buffer.position(lastPosition);
            // Discard all ranges that are not serialized.
            List<Range> retainedRange = acknowledgedRanges.subList(0, rangesAdded + 1);
            // Create a copy of the list, because the original list is immutable and despite the sublist operation, will retain all used memory!
            acknowledgedRanges = new ArrayList<>(retainedRange);
        }
        frameBytes = new byte[buffer.position()];
        buffer.flip();
        buffer.get(frameBytes);
    }

    @Override
    public int getFrameLength() {
        if (frameBytes != null) {
            return frameBytes.length;
        }
        else {
            throw new IllegalStateException("frame length not known for parsed frames");
        }
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put(frameBytes);
    }

    public AckFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException, IntegerTooLargeException, TransportError {
        log.debug("Parsing AckFrame");
        acknowledgedRanges = new ArrayList<>();

        int frameType = buffer.get();

        largestAcknowledged = VariableLengthInteger.parseLong(buffer);

        // Kwik does not support ack delay larger than what fits in an int. An int is large enough to hold the largest
        // ack delay that makes sense (even with a delay exponent of 0, MAX_INT is 2147 seconds, approx. half an hour).
        ackDelay = parseVariableLengthIntegerLimitedToInt(buffer);

        int ackBlockCount = VariableLengthInteger.parseInt(buffer);

        long currentSmallest = largestAcknowledged;
        // The smallest of the first block is the largest - (rangeSize - 1).
        int firstAckRange = parseVariableLengthIntegerLimitedToInt(buffer);  // A range larger than 2^31 is hardly imaginable.
        currentSmallest -= addAcknowledgeRange(largestAcknowledged, 1 + firstAckRange) - 1;

        for (int i = 0; i < ackBlockCount; i++) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.3.1:
            // "Each Gap indicates a range of packets that are not being
            //   acknowledged.  The number of packets in the gap is one higher than
            //   the encoded value of the Gap Field."
            int gapSize = parseVariableLengthIntegerLimitedToInt(buffer) + 1;
            // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.3.1:
            // "Each ACK Block acknowledges a contiguous range of packets by
            //   indicating the number of acknowledged packets that precede the
            //   largest packet number in that block.  A value of zero indicates that
            //   only the largest packet number is acknowledged."
            int contiguousPacketsPreceding = parseVariableLengthIntegerLimitedToInt(buffer) + 1;
            // The largest of the next range is the current smallest - (gap size + 1), because the gap size counts the
            // ones not being present, and we need the first (below) being present.
            // The new current smallest is largest of the next range - (range size - 1)
            //                             == current smallest - (gap size + 1) - (range size - 1)
            //                             == current smallest - gap size - range size
            currentSmallest -= (gapSize + addAcknowledgeRange(currentSmallest - gapSize - 1, contiguousPacketsPreceding));
        }

        if (frameType == 0x03) {
            // Parse ECN counts (in order to read the complete frame from the buffer)
            VariableLengthInteger.parseLong(buffer);
            VariableLengthInteger.parseLong(buffer);
            VariableLengthInteger.parseLong(buffer);
        }
        return this;
    }

    private int addAcknowledgeRange(long largestOfRange, int rangeSize) throws TransportError {
        if (largestOfRange - rangeSize + 1 < 0) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3.1
            // If any computed packet number is negative, an endpoint MUST generate a connection error of type FRAME_ENCODING_ERROR.
            throw new TransportError(QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR, "negative packet number in ACK frame");
        }
        acknowledgedRanges.add(new Range(largestOfRange - rangeSize + 1, largestOfRange));
        return rangeSize;
    }

    /**
     * Returns the acked packet numbers in reverse sorted order (so the largest first)
     * @return
     */
    public Stream<Long> getAckedPacketNumbers() {
        return acknowledgedRanges.stream().flatMap(r -> r.stream());
    }

    /**
     * Returns the acked packet numbers greater or equal the given minimum in reverse sorted order (so the largest first)
     * @return
     */
    public Stream<Long> getAckedPacketNumbers(long minimum) {
        return acknowledgedRanges.stream()
                .filter(r -> r.getLargest() >= minimum)
                .flatMap(r -> r.stream(minimum));
    }

    /**
     * Returns the acked ranges in reverse sorted order (so largest first)
     * @return
     */
    public List<Range> getAcknowledgedRanges() {
        return acknowledgedRanges;
    }

    @Override
    public String toString() {
        if (stringRepresentation == null) {
            stringRepresentation = acknowledgedRanges.stream()
                    .map(r -> r.size() == 1? "" + r.getLargest(): "" + r.getLargest() + "-" + r.getSmallest())
                    .collect(Collectors.joining(","));
        }
        return "AckFrame[" + stringRepresentation + "|\u0394" + (ackDelay * delayScale) / 1000  + "]";
    }

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-2
    // "All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered ack-eliciting."
    @Override
    public boolean isAckEliciting() {
        return false;
    }

    public long getLargestAcknowledged() {
        return largestAcknowledged;
    }

    /**
     * Get ack delay in milliseconds.
     * @return
     */
    public int getAckDelay() {
        return (ackDelay * delayScale) / 1000;
    }

    public void setDelayExponent(int exponent) {
        delayScale = (int) Math.pow(2, exponent);
    }

    public void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
