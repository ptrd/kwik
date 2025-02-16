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
package tech.kwik.core.packet;


import tech.kwik.core.QuicConstants;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.generic.IntegerTooLargeException;
import tech.kwik.core.generic.InvalidIntegerEncodingException;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.core.impl.DecryptionException;
import tech.kwik.core.impl.InvalidPacketException;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;

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

    public static boolean isLongHeaderPacket(byte flags, Version quicVersion) {
        return (flags & 0b1100_0000) == 0b1100_0000;
    }

    public static Class determineType(byte flags, Version version) {
        int type = (flags & 0x30) >> 4;
        if (InitialPacket.isInitialType(type, version)) {
            return InitialPacket.class;
        }
        else if (HandshakePacket.isHandshake(type, version)) {
            return HandshakePacket.class;
        }
        else if (RetryPacket.isRetry(type, version)) {
            return RetryPacket.class;
        }
        else if (ZeroRttPacket.isZeroRTT(type, version)) {
            return ZeroRttPacket.class;
        }
        else {
            // Impossible, conditions are exhaustive
            throw new RuntimeException();
        }
    }

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
    public byte[] generatePacketBytes(Aead aead) {
        assert(packetNumber >= 0);

        ByteBuffer packetBuffer = ByteBuffer.allocate(MAX_PACKET_SIZE);
        generateFrameHeaderInvariant(packetBuffer);
        generateAdditionalFields(packetBuffer);
        byte[] encodedPacketNumber = encodePacketNumber(packetNumber);
        ByteBuffer frameBytes = generatePayloadBytes(encodedPacketNumber.length);
        addLength(packetBuffer, encodedPacketNumber.length, frameBytes.limit());
        packetBuffer.put(encodedPacketNumber);

        protectPacketNumberAndPayload(packetBuffer, encodedPacketNumber.length, frameBytes, 0, aead);

        packetBuffer.limit(packetBuffer.position());
        packetSize = packetBuffer.limit();

        byte[] packetBytes = new byte[packetBuffer.position()];
        packetBuffer.rewind();
        packetBuffer.get(packetBytes);

        packetSize = packetBytes.length;
        return packetBytes;
    }

    @Override
    protected void checkReservedBits(byte decryptedFlags) throws TransportError {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
        // "An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing both
        //  packet and header protection, as a connection error of type PROTOCOL_VIOLATION. "
        if ((decryptedFlags & 0x0c) != 0) {
            throw new TransportError(QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION, "Reserved bits in long header packet are not zero");
        }
    }

    @Override
    public int estimateLength(int additionalPayload) {
        int packetNumberSize = computePacketNumberSize(packetNumber);
        int payloadSize = getFrames().stream().mapToInt(f -> f.getFrameLength()).sum() + additionalPayload;
        int padding = Integer.max(0,4 - packetNumberSize - payloadSize);
        return 1
                + 4
                + 1 + destinationConnectionId.length
                + 1 + sourceConnectionId.length
                + estimateAdditionalFieldsLength()
                + (payloadSize + 1 > 63? 2: 1)
                + computePacketNumberSize(packetNumber)
                + payloadSize
                + padding
                // https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection-sample
                // "The ciphersuites defined in [TLS13] - (...) - have 16-byte expansions..."
                + 16;
    }

    protected void generateFrameHeaderInvariant(ByteBuffer packetBuffer) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-long-header-packets
        // "Long Header Packet {
        //    Header Form (1) = 1,
        //    Fixed Bit (1) = 1,
        //    Long Packet Type (2),
        //    Type-Specific Bits (4),"
        //    Version (32),
        //    Destination Connection ID Length (8),
        //    Destination Connection ID (0..160),
        //    Source Connection ID Length (8),
        //    Source Connection ID (0..160),
        //    Type-Specific Payload (..),
        //  }

        // Packet type and packet number length
        byte flags = encodePacketNumberLength((byte) (0b1100_0000 | (getPacketType() << 4)), packetNumber);
        encodePacketNumberLength(flags, packetNumber);
        packetBuffer.put(flags);
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
    public void parse(ByteBuffer buffer, Aead aead, long largestPacketNumber, Logger log, int sourceConnectionIdLength) throws DecryptionException, InvalidPacketException, TransportError {
        log.debug("Parsing " + this.getClass().getSimpleName());
        if (buffer.position() != 0) {
            // parsePacketNumberAndPayload method requires packet to start at 0.
            throw new IllegalStateException();
        }
        if (buffer.remaining() < MIN_PACKET_LENGTH) {
            throw new InvalidPacketException();
        }
        byte flags = buffer.get();
        checkPacketType((flags & 0x30) >> 4);

        boolean matchingVersion = Version.parse(buffer.getInt()).equals(this.quicVersion);
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
            length = VariableLengthInteger.parseInt(buffer);
        }
        catch (IllegalArgumentException | InvalidIntegerEncodingException | IntegerTooLargeException invalidInt) {
            throw new TransportError(QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR);
        }
        log.debug("Length (PN + payload): " + length);

        try {
            parsePacketNumberAndPayload(buffer, flags, length, aead, largestPacketNumber, log);
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

    protected void checkPacketType(int type) {
        if (type != getPacketType()) {
            // Programming error: this method shouldn't have been called if packet is not Initial
            throw new RuntimeException();
        }
    }

    protected abstract void parseAdditionalFields(ByteBuffer buffer) throws InvalidPacketException;
}

