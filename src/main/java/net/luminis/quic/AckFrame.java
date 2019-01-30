/*
 * Copyright © 2019 Peter Doornbosch
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
package net.luminis.quic;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.3.1
 */
public class AckFrame extends QuicFrame {

    private byte[] frameBytes;
    private int largestAcknowledged;
    private int ackDelay;
    private List<Integer> acknowledgedPacketNumbers;

    public AckFrame() {
    }

    public AckFrame(Version quicVersion, int packetNumber) {
        largestAcknowledged = packetNumber;
        acknowledgedPacketNumbers = List.of(largestAcknowledged);
        
        ByteBuffer buffer = ByteBuffer.allocate(100);

        if (quicVersion.equals(Version.IETF_draft_14)) {
            buffer.put((byte) 0x0d);
        }
        else if (quicVersion.atLeast(Version.IETF_draft_17)) {
            buffer.put((byte) 0x02);
        }
        else if (quicVersion.atLeast(Version.IETF_draft_15)) {
            buffer.put((byte) 0x1a);
        }

        buffer.put(encodeVariableLengthInteger(packetNumber));
        buffer.put(encodeVariableLengthInteger(0));
        buffer.put(encodeVariableLengthInteger(0));
        buffer.put(encodeVariableLengthInteger(0));

        frameBytes = new byte[buffer.position()];
        buffer.flip();
        buffer.get(frameBytes);
    }

    public AckFrame parse(ByteBuffer buffer, Logger log) {
        log.debug("Parsing AckFrame");
        acknowledgedPacketNumbers = new ArrayList<>();

        buffer.get();

        largestAcknowledged = QuicPacket.parseVariableLengthInteger(buffer);
        acknowledgedPacketNumbers.add(largestAcknowledged);

        ackDelay = QuicPacket.parseVariableLengthInteger(buffer);

        int ackBlockCount = QuicPacket.parseVariableLengthInteger(buffer);

        int currentSmallest = largestAcknowledged;
        currentSmallest -= addAcknowledgeRange(largestAcknowledged, QuicPacket.parseVariableLengthInteger(buffer));

        // For the time being, we only parse simple Ack frames, without Additional Ack Block's
        for (int i = 0; i < ackBlockCount; i++) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.3.1:
            // "Each Gap indicates a range of packets that are not being
            //   acknowledged.  The number of packets in the gap is one higher than
            //   the encoded value of the Gap Field."
            int gapSize = QuicPacket.parseVariableLengthInteger(buffer) + 1;
            // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.3.1:
            // "Each ACK Block acknowledges a contiguous range of packets by
            //   indicating the number of acknowledged packets that precede the
            //   largest packet number in that block.  A value of zero indicates that
            //   only the largest packet number is acknowledged."
            int contiguousPacketsPreceding = QuicPacket.parseVariableLengthInteger(buffer) + 1;
            currentSmallest -= (gapSize + addAcknowledgeRange(currentSmallest - gapSize, contiguousPacketsPreceding));
        }

        return this;
    }

    private int addAcknowledgeRange(int smallestAcknowledged, int contiguousPacketsPreceding) {
        for (int i = contiguousPacketsPreceding; i > 0 ; i--) {
            acknowledgedPacketNumbers.add(--smallestAcknowledged);
        }
        return contiguousPacketsPreceding;
    }

    public List<Integer> getAckedPacketNumbers() {
        return acknowledgedPacketNumbers;
    }

    @Override
    public String toString() {
        return "AckFrame[" + acknowledgedPacketNumbers.stream().map(i -> i.toString()).collect(Collectors.joining(",")) + "]";
    }

    @Override
    byte[] getBytes() {
        return frameBytes;
    }

    public int getLargestAcknowledged() {
        return largestAcknowledged;
    }

    public int getAckDelay() {
        return ackDelay;
    }
}
