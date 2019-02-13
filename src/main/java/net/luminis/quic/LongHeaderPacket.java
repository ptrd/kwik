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
import java.util.List;
import java.util.stream.Collectors;

import static net.luminis.quic.EncryptionLevel.Initial;

// https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.2
public abstract class LongHeaderPacket extends QuicPacket {

    private static final int MAX_PACKET_SIZE = 1500;

    protected byte[] sourceConnectionId;
    protected byte[] destConnectionId;
    protected byte[] payload;
    protected ByteBuffer packetBuffer;
    protected int paddingLength;
    private byte[] destinationConnectionId;

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
        this.destConnectionId = destConnectionId;
        this.frames = List.of(frame);
        this.payload = frame.getBytes();
    }

    public byte[] generatePacketBytes(long packetNumber, ConnectionSecrets connectionSecrets) {
        this.packetNumber = packetNumber;
        NodeSecrets clientSecrets = connectionSecrets.getClientSecrets(getEncryptionLevel());

        packetBuffer = ByteBuffer.allocate(MAX_PACKET_SIZE);
        generateFrameHeaderInvariant();
        generateAdditionalFields();
        byte[] encodedPacketNumber = encodePacketNumber(packetNumber);
        addLength(encodedPacketNumber.length);
        packetBuffer.put(encodedPacketNumber);

        protectPacketNumberAndPayload(packetBuffer, encodedPacketNumber.length, ByteBuffer.wrap(payload), paddingLength, clientSecrets);

        packetBuffer.limit(packetBuffer.position());
        packetSize = packetBuffer.limit();

        byte[] packetBytes = new byte[packetBuffer.position()];
        packetBuffer.rewind();
        packetBuffer.get(packetBytes);

        packetSize = packetBytes.length;
        return packetBytes;
    }

    protected void generateFrameHeaderInvariant() {
        // Packet type
        byte packetType = getPacketType();
        packetBuffer.put(packetType);
        // Version
        packetBuffer.put(quicVersion.getBytes());
        // DCIL / SCIL
        byte dcil = (byte) ((destConnectionId.length - 3) << 4);
        byte scil = (byte) (sourceConnectionId.length - 3);
        packetBuffer.put((byte) (dcil | scil));
        // Destination connection id
        packetBuffer.put(destConnectionId);
        // Source connection id, 8 bytes
        packetBuffer.put(sourceConnectionId);
    }

    protected abstract byte getPacketType();

    protected abstract void generateAdditionalFields();

    private void addLength(int packetNumberLength) {
        int estimatedPacketLength = packetBuffer.position() + packetNumberLength + payload.length + 16;   // 16 is what encryption adds, note that final length is larger due to adding packet length
        paddingLength = 0;
        if (getEncryptionLevel() == Initial && packetNumber == 0) {
            // Initial packet should at least be 1200 bytes (https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-14)
            if (estimatedPacketLength < 1200)
                paddingLength = 1200 - estimatedPacketLength;
        }
        int packetLength = payload.length + paddingLength + 16 + packetNumberLength;
        byte[] length = encodeVariableLengthInteger(packetLength);
        packetBuffer.put(length);
    }

    public LongHeaderPacket parse(ByteBuffer buffer, ConnectionSecrets connectionSecrets, Logger log) {
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

        byte dcilScil = buffer.get();
        int dstConnIdLength = ((dcilScil & 0xf0) >> 4) + 3;
        int srcConnIdLength = (dcilScil & 0x0f) + 3;

        destinationConnectionId = new byte[dstConnIdLength];
        buffer.get(destinationConnectionId);
        log.debug("Destination connection id", destinationConnectionId);
        sourceConnectionId = new byte[srcConnIdLength];
        buffer.get(sourceConnectionId);
        log.debug("Source connection id", sourceConnectionId);

        parseAdditionalFields(buffer);

        int length = parseVariableLengthInteger(buffer);
        log.debug("Length (PN + payload): " + length);

        NodeSecrets serverSecrets = connectionSecrets.getServerSecrets(getEncryptionLevel());
        if (quicVersion.atLeast(Version.IETF_draft_17)) {
            parsePacketNumberAndPayload(buffer, flags, length, serverSecrets, log);
        }
        else {
            int protectedPackageNumberLength = 1;   // Assuming packet number is 1 byte (which is of course not always the case...)
            byte[] protectedPackageNumber = new byte[protectedPackageNumberLength];
            buffer.get(protectedPackageNumber);

            int currentPosition = buffer.position();
            byte[] frameHeader = new byte[buffer.position()];
            buffer.position(0);
            buffer.get(frameHeader);
            buffer.position(currentPosition);

            byte[] payload = new byte[length - protectedPackageNumberLength];
            buffer.get(payload, 0, length - protectedPackageNumberLength);

            packetNumber = unprotectPacketNumber(payload, protectedPackageNumber, serverSecrets);
            log.decrypted("Unprotected packet number: " + packetNumber);

            log.debug("Encrypted payload", payload);

            frameHeader[frameHeader.length - 1] = (byte) packetNumber;   // Assuming packet number is 1 byte
            log.debug("Frame header", frameHeader);

            byte[] frameBytes = decryptPayload(payload, frameHeader, packetNumber, serverSecrets);
            log.decrypted("Decrypted payload", frameBytes);

            frames = new ArrayList<>();
            parseFrames(frameBytes, log);
        }

        packetSize = buffer.position() - startPosition;
        return this;
    }

    @Override
    public String toString() {
        return "Packet "
                + getEncryptionLevel().name().charAt(0) + "|"
                + packetNumber + "|"
                + "L" + "|"
                + packetSize + "|"
                + frames.size() + "  "
                + frames.stream().map(f -> f.toString()).collect(Collectors.joining(" "));
    }

    public byte[] getSourceConnectionId() {
        return sourceConnectionId;
    }

    public byte[] getDestinationConnectionId() {
        return destConnectionId;
    }

    protected abstract void checkPacketType(byte b);

    protected abstract void parseAdditionalFields(ByteBuffer buffer);
}

