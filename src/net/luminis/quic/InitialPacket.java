package net.luminis.quic;

import java.nio.ByteBuffer;

public class InitialPacket extends LongHeaderPacket {

    public InitialPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, int packetNumber, byte[] payload, ConnectionSecrets connectionSecrets) {
        super(quicVersion, sourceConnectionId, destConnectionId, packetNumber, payload, connectionSecrets);
    }

    public InitialPacket(ConnectionSecrets connectionSecrets) {
        super(connectionSecrets);
    }

    protected void generateAdditionalFields() {
        // Token length (variable-length integer)
        packetBuffer.put((byte) 0x00);
    }

    public void parse(ByteBuffer buffer, Logger log) {
        log.debug("Parsing InitialPacket");
        if (buffer.get() != (byte) 0xff) {
            // Programming error: this method shouldn't have been called if packet is not Initial
            throw new RuntimeException();
        }

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
        byte[] srcConnId = new byte[srcConnIdLength];
        buffer.get(srcConnId);
        log.debug("Source connection id", srcConnId);

        int tokenLength = buffer.get();
        if (tokenLength > 0) {
            buffer.position(buffer.position() + tokenLength);
        }

        int length = parseVariableLengthInteger(buffer);
        log.debug("Length (PN + payload): " + length);

        int protectedPackageNumber = buffer.get() & 0xff;   // TODO: assuming pn is 1 byte

        int currentPosition = buffer.position();
        byte[] frameHeader = new byte[buffer.position()];
        buffer.position(0);
        buffer.get(frameHeader);
        buffer.position(currentPosition);

        byte[] payload = new byte[length-1];  // 1 byte packet number
        buffer.get(payload, 0, length-1);

        int packetNumber = unprotectPacketNumber(payload, protectedPackageNumber, connectionSecrets.serverSecrets);
        log.debug("Packet number: " + packetNumber);

        log.debug("Encrypted payload", payload);

        frameHeader[frameHeader.length - 1] = (byte) packetNumber;   // TODO: assuming packet number is 1 byte
        log.debug("Frame header", frameHeader);

        byte[] frames = decryptPayload(payload, frameHeader, 0, connectionSecrets.serverSecrets);
        log.debug("Decrypted payload", frames);
    }

}
