package net.luminis.quic;

import net.luminis.tls.TlsState;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class ShortHeaderPacket extends QuicPacket {

    private byte[] destConnectionId;
    private byte[] packetBytes;
    private int packetSize;

    /**
     * Constructs an empty short header packet for use with the parse() method.
     * @param quicVersion
     */
    public ShortHeaderPacket(Version quicVersion) {
        this.quicVersion = quicVersion;
    }

    /**
     * Constructs a short header packet for sending (client role).
     * @param quicVersion
     * @param destinationConnectionId
     * @param packetNumber
     * @param frame
     * @param connectionSecrets
     */
    public ShortHeaderPacket(Version quicVersion, byte[] destinationConnectionId, int packetNumber, QuicFrame frame, ConnectionSecrets connectionSecrets) {
        this.quicVersion = quicVersion;
        this.destConnectionId = destinationConnectionId;
        this.packetNumber = packetNumber;
        frames = List.of(frame);

        NodeSecrets clientSecrets = connectionSecrets.getClientSecrets(getEncryptionLevel());

        ByteBuffer buffer = ByteBuffer.allocate(MAX_PACKET_SIZE);
        byte flags = 0x30;
        buffer.put(flags);
        buffer.put(destinationConnectionId);

        byte[] encodedPacketNumber = encodePacketNumber(packetNumber);
        buffer.put(encodedPacketNumber);

        protectPayload(buffer, encodedPacketNumber.length, frame.getBytes(), 0, clientSecrets);

        buffer.limit(buffer.position());
        packetSize = buffer.limit();
        packetBytes = new byte[packetSize];
        buffer.rewind();
        buffer.get(packetBytes);
    }

    public ShortHeaderPacket parse(ByteBuffer buffer, QuicConnection connection, ConnectionSecrets connectionSecrets, TlsState tlsState, Logger log) {
        int startPosition = buffer.position();
        log.debug("Parsing " + this.getClass().getSimpleName());
        checkPacketType(buffer.get());

        byte[] sourceConnectionId = connection.getSourceConnectionId();
        byte[] packetConnectionId = new byte[sourceConnectionId.length];
        buffer.get(packetConnectionId);
        log.debug("Destination connection id", packetConnectionId);

        int protectedPackageNumberLength = 1;
        byte[] protectedPackageNumber = new byte[protectedPackageNumberLength];
        buffer.get(protectedPackageNumber);

        int currentPosition = buffer.position();
        byte[] frameHeader = new byte[buffer.position()];
        buffer.position(0);
        buffer.get(frameHeader);
        buffer.position(currentPosition);

        int length = buffer.limit();
        byte[] payload = new byte[length - buffer.position()];
        buffer.get(payload);

        NodeSecrets serverSecrets = connectionSecrets.getServerSecrets(EncryptionLevel.App);

        packetNumber = unprotectPacketNumber(payload, protectedPackageNumber, serverSecrets);
        log.decrypted("Unprotected packet number: " + packetNumber);

        log.debug("Encrypted payload", payload);

        frameHeader[frameHeader.length - 1] = (byte) packetNumber;   // TODO: assuming packet number is 1 byte
        log.debug("Frame header", frameHeader);

        byte[] frameBytes = decryptPayload(payload, frameHeader, packetNumber, serverSecrets);
        log.decrypted("Decrypted payload", frameBytes);

        frames = new ArrayList<>();
        parseFrames(frameBytes, connection, connectionSecrets, tlsState, log);

        packetSize = buffer.position() - startPosition;
        return this;
    }

    protected EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.App;
    }

    @Override
    public byte[] getBytes() {
        return packetBytes;
    }

    @Override
    public void accept(PacketProcessor processor) {
        processor.process(this);
    }

    protected void checkPacketType(byte flags) {
        if ((flags & 0x80) != 0x00) {
            // Programming error: this method shouldn't have been called if packet is not a Short Frame
            throw new RuntimeException();
        }
    }

    @Override
    public String toString() {
        return "Packet "
                + getEncryptionLevel().name().charAt(0) + "|"
                + packetNumber + "|"
                + "S" + "|"
                + packetSize + "|"
                + frames.size() + "  "
                + frames.stream().map(f -> f.toString()).collect(Collectors.joining(" "));
    }

}
