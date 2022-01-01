/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic.packet;


import net.luminis.quic.*;
import net.luminis.quic.crypto.Keys;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.log.Logger;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

// https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.2
public abstract class LongHeaderPacket extends QuicPacket {

    private static final int MAX_PACKET_SIZE = 1500;
    // Minimal length for a valid packet:  type version dcid len dcid scid len scid length packet number payload
    private static int MIN_PACKET_LENGTH = 1 +  4 +     1 +      0 +  1 +      0 +  1 +    1 +    1;

    protected byte[] sourceConnectionId;

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
        if (frames == null) {
            throw new IllegalArgumentException();
        }
        this.quicVersion = quicVersion;
        this.sourceConnectionId = sourceConnectionId;
        this.destinationConnectionId = destConnectionId;
        this.frames = frames;
    }

    @Override
    public byte[] generatePacketBytes(Long packetNumber, Keys keys) {
        this.packetNumber = packetNumber;

        ByteBuffer packetBuffer = ByteBuffer.allocate(MAX_PACKET_SIZE);
        generateFrameHeaderInvariant(packetBuffer);
        generateAdditionalFields(packetBuffer);
        byte[] encodedPacketNumber = encodePacketNumber(packetNumber);
        ByteBuffer frameBytes = generatePayloadBytes(encodedPacketNumber.length);
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

    @Override
    public int estimateLength(int additionalPayload) {
        int payloadLength = getFrames().stream().mapToInt(f -> f.getFrameLength()).sum() + additionalPayload;
        return 1
                + 4
                + 1 + destinationConnectionId.length
                + 1 + sourceConnectionId.length
                + estimateAdditionalFieldsLength()
                + (payloadLength + 1 > 63? 2: 1)
                + 1  // packet number length: will usually be just 1, actual value cannot be computed until packet number is known
                + payloadLength
                // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.2
                // "The ciphersuites defined in [TLS13] - (...) - have 16-byte expansions..."
                + 16;
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
        // Source connection id
        packetBuffer.put(sourceConnectionId);
    }

    protected abstract byte getPacketType();

    protected abstract void generateAdditionalFields(ByteBuffer packetBuffer);

    protected abstract int estimateAdditionalFieldsLength();

    private void addLength(ByteBuffer packetBuffer, int packetNumberLength, int payloadSize) {
        int packetLength = payloadSize + 16 + packetNumberLength;   // 16 is what encryption adds, note that final length is larger due to adding packet length
        VariableLengthInteger.encode(packetLength, packetBuffer);
    }

    @Override
    public void parse(ByteBuffer buffer, Keys keys, long largestPacketNumber, Logger log, int sourceConnectionIdLength) throws DecryptionException, InvalidPacketException {
        log.debug("Parsing " + this.getClass().getSimpleName());
        if (buffer.position() != 0) {
            // parsePacketNumberAndPayload method requires packet to start at 0.
            throw new IllegalStateException();
        }
        if (buffer.remaining() < MIN_PACKET_LENGTH) {
            throw new InvalidPacketException();
        }
        byte flags = buffer.get();
        checkPacketType(flags);

        boolean matchingVersion = false;
        try {
            matchingVersion = Version.parse(buffer.getInt()) == this.quicVersion;
        } catch (UnknownVersionException e) {}

        if (! matchingVersion) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-5.2
            // "... packets are discarded if they indicate a different protocol version than that of the connection..."
            throw new InvalidPacketException("Version does not match version of the connection");
        }

        int dstConnIdLength = buffer.get();
        // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-17.2
        // "In QUIC version 1, this value MUST NOT exceed 20.  Endpoints that receive a version 1 long header with a
        // value larger than 20 MUST drop the packet."
        if (dstConnIdLength < 0 || dstConnIdLength > 20) {
            throw new InvalidPacketException();
        }
        if (buffer.remaining() < dstConnIdLength) {
            throw new InvalidPacketException();
        }
        destinationConnectionId = new byte[dstConnIdLength];
        buffer.get(destinationConnectionId);

        int srcConnIdLength = buffer.get();
        if (srcConnIdLength < 0 || srcConnIdLength > 20) {
            throw new InvalidPacketException();
        }
        if (buffer.remaining() < srcConnIdLength) {
            throw new InvalidPacketException();
        }
        sourceConnectionId = new byte[srcConnIdLength];
        buffer.get(sourceConnectionId);
        log.debug("Destination connection id", destinationConnectionId);
        log.debug("Source connection id", sourceConnectionId);

        parseAdditionalFields(buffer);

        int length;
        try {
            // "The length of the remainder of the packet (that is, the Packet Number and Payload fields) in bytes"
            length = VariableLengthInteger.parse(buffer);
        }
        catch (IllegalArgumentException | InvalidIntegerEncodingException invalidInt) {
            throw new InvalidPacketException();
        }
        log.debug("Length (PN + payload): " + length);

        try {
            parsePacketNumberAndPayload(buffer, flags, length, keys, largestPacketNumber, log);
        }
        finally {
            packetSize = buffer.position() - 0;
        }
    }

    @Override
    public String toString() {
        return "Packet "
                + (isProbe? "P": "")
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

    protected abstract void checkPacketType(byte b);

    protected abstract void parseAdditionalFields(ByteBuffer buffer) throws InvalidPacketException;
}

