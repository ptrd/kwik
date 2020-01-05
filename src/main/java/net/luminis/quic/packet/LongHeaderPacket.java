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
package net.luminis.quic.packet;


import net.luminis.quic.*;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.log.Logger;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

// https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.2
public abstract class LongHeaderPacket extends QuicPacket {

    private static final int MAX_PACKET_SIZE = 1500;

    protected byte[] sourceConnectionId;
    protected byte[] destinationConnectionId;

    /**
     * Constructs an empty packet for parsing a received one
     * @param quicVersion
     */
    public LongHeaderPacket(Version quicVersion) {
        this.quicVersion = quicVersion;
    }

    /**
     * Constructs a long header packet for sending (client role).
     * @param quicVersion
     * @param sourceConnectionId
     * @param destConnectionId
     * @param frame
     */
    public LongHeaderPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, QuicFrame frame) {
        this.quicVersion = quicVersion;
        this.sourceConnectionId = sourceConnectionId;
        this.destinationConnectionId = destConnectionId;
        this.frames = new ArrayList<>();
        if (frame != null) {
            this.frames.add(frame);
        }
    }

    /**
     * Constructs a long header packet for sending (client role).
     * @param quicVersion
     * @param sourceConnectionId
     * @param destConnectionId
     * @param frames
     */
    public LongHeaderPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, List<QuicFrame> frames) {
        this.quicVersion = quicVersion;
        this.sourceConnectionId = sourceConnectionId;
        this.destinationConnectionId = destConnectionId;
        this.frames = frames;
    }

    public byte[] generatePacketBytes(long packetNumber, Keys keys) {
        this.packetNumber = packetNumber;

        ByteBuffer frameBytes = ByteBuffer.allocate(MAX_PACKET_SIZE);
        frames.stream().forEachOrdered(frame -> frameBytes.put(frame.getBytes()));
        frameBytes.flip();

        ByteBuffer packetBuffer = ByteBuffer.allocate(MAX_PACKET_SIZE);
        generateFrameHeaderInvariant(packetBuffer);
        generateAdditionalFields(packetBuffer);
        byte[] encodedPacketNumber = encodePacketNumber(packetNumber);
        addLength(packetBuffer, encodedPacketNumber.length, frameBytes.limit());
        packetBuffer.put(encodedPacketNumber);

        protectPacketNumberAndPayload(packetBuffer, encodedPacketNumber.length, frameBytes, 0, keys);

        packetBuffer.limit(packetBuffer.position());
        packetSize = packetBuffer.limit();

        byte[] packetBytes = new byte[packetBuffer.position()];
        packetBuffer.rewind();
        packetBuffer.get(packetBytes);

        packetSize = packetBytes.length;
        return packetBytes;
    }

    protected void generateFrameHeaderInvariant(ByteBuffer packetBuffer) {
        // Packet type
        byte packetType = getPacketType();
        packetBuffer.put(packetType);
        // Version
        packetBuffer.put(quicVersion.getBytes());
        // DCID Len
        packetBuffer.put((byte) destinationConnectionId.length);
        // Destination connection id
        packetBuffer.put(destinationConnectionId);
        // SCID Len
        packetBuffer.put((byte) sourceConnectionId.length);
        // Source connection id, 8 bytes
        packetBuffer.put(sourceConnectionId);
    }

    protected abstract byte getPacketType();

    protected abstract void generateAdditionalFields(ByteBuffer packetBuffer);

    private void addLength(ByteBuffer packetBuffer, int packetNumberLength, int payloadSize) {
        int packetLength = payloadSize + 16 + packetNumberLength;   // 16 is what encryption adds, note that final length is larger due to adding packet length
        VariableLengthInteger.encode(packetLength, packetBuffer);
    }

    public void parse(ByteBuffer buffer, Keys keys, long largestPacketNumber, Logger log, int sourceConnectionIdLength) throws DecryptionException {
        int startPosition = buffer.position();
        log.debug("Parsing " + this.getClass().getSimpleName());
        byte flags = buffer.get();
        checkPacketType(flags);

        try {
            Version quicVersion = Version.parse(buffer.getInt());
        } catch (UnknownVersionException e) {
            // Protocol error: if it gets here, server should match the Quic version we sent
            throw new ProtocolError("Server uses unsupported Quic version");
        }

        int dstConnIdLength = buffer.get();
        destinationConnectionId = new byte[dstConnIdLength];
        buffer.get(destinationConnectionId);

        int srcConnIdLength = buffer.get();
        sourceConnectionId = new byte[srcConnIdLength];
        buffer.get(sourceConnectionId);
        log.debug("Destination connection id", destinationConnectionId);
        log.debug("Source connection id", sourceConnectionId);

        parseAdditionalFields(buffer);

        int length = VariableLengthInteger.parse(buffer);
        log.debug("Length (PN + payload): " + length);

        try {
            parsePacketNumberAndPayload(buffer, flags, length, keys, largestPacketNumber, log);
        }
        finally {
            packetSize = buffer.position() - startPosition;
        }
    }

    @Override
    public String toString() {
        return "Packet "
                + getEncryptionLevel().name().charAt(0) + "|"
                + (packetNumber >= 0? packetNumber: ".") + "|"
                + "L" + "|"
                + (packetSize >= 0? packetSize: ".") + "|"
                + frames.size() + "  "
                + frames.stream().map(f -> f.toString()).collect(Collectors.joining(" "));
    }

    public byte[] getSourceConnectionId() {
        return sourceConnectionId;
    }

    public byte[] getDestinationConnectionId() {
        return destinationConnectionId;
    }

    protected abstract void checkPacketType(byte b);

    protected abstract void parseAdditionalFields(ByteBuffer buffer);
}

