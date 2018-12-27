package net.luminis.quic;

import net.luminis.tls.TlsState;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.stream.Collectors;

public class ShortHeaderPacket extends QuicPacket {

    protected byte[] payload;
    protected byte[] destConnectionId;
    private int packetSize;


    public ShortHeaderPacket(Version quicVersion) {
        this.quicVersion = quicVersion;
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
        log.debug("Packet number: " + packetNumber);

        log.debug("Encrypted payload", payload);

        frameHeader[frameHeader.length - 1] = (byte) packetNumber;   // TODO: assuming packet number is 1 byte
        log.debug("Frame header", frameHeader);

        byte[] frameBytes = decryptPayload(payload, frameHeader, packetNumber, serverSecrets);
        log.debug("Decrypted payload", frameBytes);

        frames = new ArrayList<>();
        parseFrames(frameBytes, connection, connectionSecrets, tlsState, log);

        packetSize = buffer.position() - startPosition;
        return this;
    }

    protected EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.App;
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
