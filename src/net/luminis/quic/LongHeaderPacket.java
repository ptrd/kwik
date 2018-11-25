package net.luminis.quic;


import java.nio.ByteBuffer;

// https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.2
public abstract class LongHeaderPacket extends QuicPacket {

    private static final int MAX_PACKET_SIZE = 1500;
    
    protected final Version quicVersion;
    protected final byte[] sourceConnectionId;
    protected final byte[] destConnectionId;
    private final int packetNumber;
    protected final byte[] payload;
    private final ConnectionSecrets connectionSecrets;
    protected final ByteBuffer packetBuffer;
    private int packetNumberPosition;
    private int encodedPacketNumberSize;
    private int paddingLength;
    private byte[] encryptedPayload;

    public LongHeaderPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, int packetNumber, byte[] payload, ConnectionSecrets connectionSecrets) {
        this.quicVersion = quicVersion;
        this.sourceConnectionId = sourceConnectionId;
        this.destConnectionId = destConnectionId;
        this.packetNumber = packetNumber;
        this.payload = payload;
        this.connectionSecrets = connectionSecrets;

        packetBuffer = ByteBuffer.allocate(MAX_PACKET_SIZE);
        generateFrameHeaderInvariant();
        generateAdditionalFields();
        byte[] encodedPacketNumber = encodePacketNumber(packetNumber);
        addLength(encodedPacketNumber.length);
        addPacketNumber(encodedPacketNumber);

        generateEncryptPayload(payload);
        protectPacketNumber();

        packetBuffer.limit(packetBuffer.position());
    }

    protected void generateFrameHeaderInvariant() {
        // type (initial)
        packetBuffer.put((byte) 0xff);
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

    protected abstract void generateAdditionalFields();

    private void addLength(int packetNumberLength) {
        int estimatedPacketLength = packetBuffer.position() + packetNumberLength + payload.length + 16;   // 16 is what encryption adds, note that final length is larger due to adding packet length
        paddingLength = 0;
        // Initial packet should at least be 1200 bytes (https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-14)
        if (estimatedPacketLength < 1200)
            paddingLength = 1200 - estimatedPacketLength;
        int packetLength = payload.length + paddingLength + 16 + packetNumberLength;
        byte[] length = encodeVariableLengthInteger(packetLength);
        packetBuffer.put(length);
    }

    private void addPacketNumber(byte[] encodedPacketNumber) {
        // Remember packet number position in buffer, for protected in later.
        packetNumberPosition = packetBuffer.position();
        encodedPacketNumberSize = encodedPacketNumber.length;
        packetBuffer.put(encodedPacketNumber);
    }

    private void generateEncryptPayload(byte[] payload) {
        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
        // "The associated data, A, for the AEAD is the contents of the QUIC
        //   header, starting from the flags octet in either the short or long
        //   header, up to and including the unprotected packet number."
        int additionalDataSize = packetBuffer.position();
        byte[] additionalData = new byte[additionalDataSize];
        packetBuffer.flip();  // Prepare for reading from start
        packetBuffer.get(additionalData);  // Position is now where it was at start of this method.
        packetBuffer.limit(packetBuffer.capacity());  // Ensure we can continue writing

        byte[] paddedPayload = new byte[payload.length + paddingLength];
        System.arraycopy(payload, 0, paddedPayload, 0, payload.length);
        encryptedPayload = encryptPayload(paddedPayload, additionalData, packetNumber, connectionSecrets);
        packetBuffer.put(encryptedPayload);
    }

    private void protectPacketNumber() {
        byte[] protectedPacketNumber = createProtectedPacketNumber(encryptedPayload, 0, connectionSecrets);
        int currentPosition = packetBuffer.position();
        packetBuffer.position(packetNumberPosition);
        packetBuffer.put(protectedPacketNumber);
        packetBuffer.position(currentPosition);
    }

    public byte[] getBytes() {
        byte[] packetBytes = new byte[packetBuffer.position()];
        packetBuffer.rewind();
        packetBuffer.get(packetBytes);
        return packetBytes;
    }
}
