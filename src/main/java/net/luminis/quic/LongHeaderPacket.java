package net.luminis.quic;


import net.luminis.tls.TlsState;

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
    private int paddingLength;
    private int packetSize;

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
     * @param packetNumber
     * @param frame
     * @param connectionSecrets
     */
    public LongHeaderPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, int packetNumber, QuicFrame frame, ConnectionSecrets connectionSecrets) {
        this.quicVersion = quicVersion;
        this.sourceConnectionId = sourceConnectionId;
        this.destConnectionId = destConnectionId;
        this.packetNumber = packetNumber;
        this.frames = List.of(frame);
        this.payload = frame.getBytes();

        NodeSecrets clientSecrets = connectionSecrets.getClientSecrets(getEncryptionLevel());

        packetBuffer = ByteBuffer.allocate(MAX_PACKET_SIZE);
        generateFrameHeaderInvariant();
        generateAdditionalFields();
        byte[] encodedPacketNumber = encodePacketNumber(packetNumber);
        addLength(encodedPacketNumber.length);
        packetBuffer.put(encodedPacketNumber);

        protectPayload(packetBuffer, encodedPacketNumber.length, payload, paddingLength, clientSecrets);

        packetBuffer.limit(packetBuffer.position());
        packetSize = packetBuffer.limit();
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

    public byte[] getBytes() {
        byte[] packetBytes = new byte[packetBuffer.position()];
        packetBuffer.rewind();
        packetBuffer.get(packetBytes);
        return packetBytes;
    }

    public LongHeaderPacket parse(ByteBuffer buffer, ConnectionSecrets connectionSecrets, Logger log) {
        int startPosition = buffer.position();
        log.debug("Parsing " + this.getClass().getSimpleName());
        checkPacketType(buffer.get());

        try {
            Version quicVersion = Version.parse(buffer.getInt());
        } catch (UnknownVersionException e) {
            // Protocol error: if it gets here, server should match the Quic version we sent
            throw new ProtocolError("Server uses unsupported Quic version");
        }

        byte dcilScil = buffer.get();
        int dstConnIdLength = ((dcilScil & 0xf0) >> 4) + 3;
        int srcConnIdLength = (dcilScil & 0x0f) + 3;

        byte[] destConnId = new byte[dstConnIdLength];
        buffer.get(destConnId);
        log.debug("Destination connection id", destConnId);
        sourceConnectionId = new byte[srcConnIdLength];
        buffer.get(sourceConnectionId);
        log.debug("Source connection id", sourceConnectionId);

        parseAdditionalFields(buffer);

        int length = parseVariableLengthInteger(buffer);
        log.debug("Length (PN + payload): " + length);

        int protectedPackageNumberLength = 1;
        byte[] protectedPackageNumber = new byte[protectedPackageNumberLength];
        buffer.get(protectedPackageNumber);

        int currentPosition = buffer.position();
        byte[] frameHeader = new byte[buffer.position()];
        buffer.position(0);
        buffer.get(frameHeader);
        buffer.position(currentPosition);

        byte[] payload = new byte[length - protectedPackageNumberLength];
        buffer.get(payload, 0, length - protectedPackageNumberLength);

        NodeSecrets serverSecrets = connectionSecrets.getServerSecrets(getEncryptionLevel());

        packetNumber = unprotectPacketNumber(payload, protectedPackageNumber, serverSecrets);
        log.decrypted("Unprotected packet number: " + packetNumber);

        log.debug("Encrypted payload", payload);

        frameHeader[frameHeader.length - 1] = (byte) packetNumber;   // TODO: assuming packet number is 1 byte
        log.debug("Frame header", frameHeader);

        byte[] frameBytes = decryptPayload(payload, frameHeader, packetNumber, serverSecrets);
        log.decrypted("Decrypted payload", frameBytes);

        frames = new ArrayList<>();
        parseFrames(frameBytes, log);

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

    public int getPacketNumber() {
        return packetNumber;
    }

    protected abstract void checkPacketType(byte b);

    protected abstract void parseAdditionalFields(ByteBuffer buffer);
}

