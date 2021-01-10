/*
 * Copyright © 2019, 2020 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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
package net.luminis.quic.frame;

import net.luminis.quic.InvalidIntegerEncodingException;
import net.luminis.quic.VariableLengthInteger;
import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.3.1
 */
public class AckFrame extends QuicFrame {

    public static final int MAX_FRAME_SIZE = 1000;  // Should be large enough; leave some space for packet overhead.

    private byte[] frameBytes;
    private long largestAcknowledged;
    private int ackDelay;
    private List<Long> acknowledgedPacketNumbers;
    // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-19.3
    // "The "ack_delay_exponent" defaults to 3, or a multiplier of 8"
    private int delayScale = 8;
    private String stringRepresentation = "";

    public AckFrame() {
    }

    public AckFrame(long packetNumber) {
        this(Version.getDefault(), packetNumber);
    }

    public AckFrame(Version quicVersion, long packetNumber) {
        largestAcknowledged = (int) packetNumber;
        acknowledgedPacketNumbers = List.of(largestAcknowledged);
        stringRepresentation = String.valueOf(largestAcknowledged);

        ByteBuffer buffer = ByteBuffer.allocate(MAX_FRAME_SIZE);
        buffer.put((byte) 0x02);

        VariableLengthInteger.encode(packetNumber, buffer);
        VariableLengthInteger.encode(0, buffer);
        VariableLengthInteger.encode(0, buffer);
        VariableLengthInteger.encode(0, buffer);

        frameBytes = new byte[buffer.position()];
        buffer.flip();
        buffer.get(frameBytes);
    }

    public AckFrame(List<Long> packetNumbers) {
        this(Version.getDefault(), packetNumbers);
    }

    public AckFrame(Version quicVersion, List<Long> packetNumbers) {
        this(quicVersion, packetNumbers, 0);
    }

    public AckFrame(Version quicVersion, List<Long> packetNumbers, int ackDelay) {
        this.ackDelay = ackDelay * 1000 / delayScale;
        if (packetNumbers.isEmpty()) {
            throw new IllegalArgumentException();
        }
        acknowledgedPacketNumbers = packetNumbers.stream().sorted(Comparator.reverseOrder()).collect(Collectors.toList());
        largestAcknowledged = acknowledgedPacketNumbers.get(0);

        ByteBuffer buffer = ByteBuffer.allocate(MAX_FRAME_SIZE);
        buffer.put((byte) 0x02);

        VariableLengthInteger.encode(largestAcknowledged, buffer);
        VariableLengthInteger.encode(ackDelay, buffer);
        ArrayList<List<Long>> ranges = split(acknowledgedPacketNumbers);
        VariableLengthInteger.encode(ranges.size() - 1, buffer);
        VariableLengthInteger.encode(ranges.get(0).size() - 1, buffer);

        for (int i = 1; i < ranges.size(); i++) {
            long prev = getLastElement(ranges.get(i-1));
            long next = ranges.get(i).get(0);
            int gap = (int) (prev - next - 2);
            int block = ranges.get(i).size() - 1;
            VariableLengthInteger.encode(gap, buffer);
            VariableLengthInteger.encode(block, buffer);
        }

        if (!ranges.isEmpty()) {
            stringRepresentation = ranges.stream().map(range ->
                    range.size() == 1 ?
                            range.get(0).toString() :
                            range.get(0).toString() + "-" + range.get(range.size() - 1).toString())
                    .collect(Collectors.joining(","));
        }
        else {
            stringRepresentation = String.valueOf(largestAcknowledged);
        }

        frameBytes = new byte[buffer.position()];
        buffer.flip();
        buffer.get(frameBytes);
    }

    private ArrayList<List<Long>> split(List<Long> packetNumbers) {
        return packetNumbers.stream().collect(
                ArrayList::new,
                (result, element) -> {
                    if (result.isEmpty()) {
                        result.add(new ArrayList<>());
                        getLastElement(result).add(element);
                    }
                    else if (getLastElement(getLastElement(result)) == element + 1) {
                        getLastElement(result).add(element);
                    }
                    else {
                        result.add(new ArrayList<>());
                        getLastElement(result).add(element);
                    }
                },
                ArrayList::addAll
                );
    }

    private static <E> E getLastElement(List<E> list) {
        return list.get(list.size()-1);
    }

    public AckFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        log.debug("Parsing AckFrame");
        acknowledgedPacketNumbers = new ArrayList<>();

        buffer.get();  // Eat type.

        largestAcknowledged = VariableLengthInteger.parseLong(buffer);

        // Parse as long to protect to against buggy peers. Convert to int as MAX_INT is large enough to hold the
        // largest ack delay that makes sense (even with an delay exponent of 0, MAX_INT is approx 2147 seconds, approx. half an hour).
        ackDelay = (int) VariableLengthInteger.parseLong(buffer);

        int ackBlockCount = (int) VariableLengthInteger.parseLong(buffer);

        long currentSmallest = largestAcknowledged;
        // The smallest of the first block is the largest - (rangeSize - 1).
        currentSmallest -= addAcknowledgeRange(largestAcknowledged, 1 + VariableLengthInteger.parse(buffer)) - 1;

        for (int i = 0; i < ackBlockCount; i++) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.3.1:
            // "Each Gap indicates a range of packets that are not being
            //   acknowledged.  The number of packets in the gap is one higher than
            //   the encoded value of the Gap Field."
            int gapSize = VariableLengthInteger.parse(buffer) + 1;
            // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.3.1:
            // "Each ACK Block acknowledges a contiguous range of packets by
            //   indicating the number of acknowledged packets that precede the
            //   largest packet number in that block.  A value of zero indicates that
            //   only the largest packet number is acknowledged."
            int contiguousPacketsPreceding = VariableLengthInteger.parse(buffer) + 1;
            // The largest of the next range is the current smallest - (gap size + 1), because the gap size counts the
            // ones not being present, and we need the first (below) being present.
            // The new current smallest is largest of the next range - (range size - 1)
            //                             == current smallest - (gap size + 1) - (range size - 1)
            //                             == current smallest - gap size - range size
            currentSmallest -= (gapSize + addAcknowledgeRange(currentSmallest - gapSize - 1, contiguousPacketsPreceding));
        }

        return this;
    }

    private int addAcknowledgeRange(long largestOfRange, int rangeSize) {
        for (int i = 0; i < rangeSize; i++) {
            acknowledgedPacketNumbers.add(largestOfRange - i);
        }

        if (! stringRepresentation.isEmpty()) {
            stringRepresentation += ",";
        }
        stringRepresentation += rangeSize > 1?
                largestOfRange + "-" + (largestOfRange - rangeSize + 1):
                largestOfRange;

        return rangeSize;
    }

    public List<Long> getAckedPacketNumbers() {
        return acknowledgedPacketNumbers;
    }

    @Override
    public String toString() {
        return "AckFrame[" + stringRepresentation + "|\u0394" + (ackDelay * delayScale) / 1000  + "]";
    }

    @Override
    public byte[] getBytes() {
        return frameBytes;
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

    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}
