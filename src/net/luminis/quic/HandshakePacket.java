package net.luminis.quic;

import net.luminis.tls.TlsState;

import java.nio.ByteBuffer;

public class HandshakePacket extends LongHeaderPacket {

    public HandshakePacket(Version quicVersion, ConnectionSecrets connectionSecrets, TlsState tlsState) {
        super(quicVersion, connectionSecrets, tlsState);
    }

    @Override
    protected void generateAdditionalFields() {
    }

    public void parse(ByteBuffer buffer, Logger log) {
        log.debug("Parsing HandshakePacket");
        if (buffer.get() != (byte) 0xfd) {
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

        byte[] payload = new byte[length-protectedPackageNumberLength];
        buffer.get(payload, 0, length-protectedPackageNumberLength);

        int packetNumber = unprotectPacketNumber(payload, protectedPackageNumber, connectionSecrets.serverSecrets);
        log.debug("Packet number: " + packetNumber);

        log.debug("Encrypted payload", payload);

        frameHeader[frameHeader.length - 1] = (byte) packetNumber;   // TODO: assuming packet number is 1 byte
        log.debug("Frame header", frameHeader);

        byte[] frames = decryptPayload(payload, frameHeader, 0, connectionSecrets.serverSecrets);
        log.debug("Decrypted payload", frames);
        parseFrames(frames, log);
    }

}
