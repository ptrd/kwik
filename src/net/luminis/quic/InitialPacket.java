package net.luminis.quic;

import net.luminis.tls.TlsState;

import java.nio.ByteBuffer;

public class InitialPacket extends LongHeaderPacket {

    private TlsState tlsState;

    public InitialPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, int packetNumber, byte[] payload, ConnectionSecrets connectionSecrets) {
        super(quicVersion, sourceConnectionId, destConnectionId, packetNumber, payload, connectionSecrets);
    }

    public InitialPacket(Version quicVersion, ConnectionSecrets connectionSecrets, TlsState tlsState) {
        super(quicVersion, connectionSecrets);
        this.tlsState = tlsState;
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

        int protectedPackageNumberLength = 1;   // TODO: assuming pn is 1 byte
        byte[] protectedPackageNumber = new byte[protectedPackageNumberLength];
        buffer.get(protectedPackageNumber);

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
        parseFrames(frames, log);
    }

    private void parseFrames(byte[] frames, Logger log) {
        ByteBuffer buffer = ByteBuffer.wrap(frames);

        while (buffer.remaining() > 0) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-12.4
            // "Each frame begins with a Frame Type, indicating its type, followed by additional type-dependent fields"
            int frameType = buffer.get();
            switch (frameType) {
                case 0x00:
                    // Padding
                    break;
                case 0x0d:
                    if (quicVersion == Version.IETF_draft_14)
                        new AckFrame().parse(buffer, log);
                    else
                        throw new NotYetImplementedException();
                    break;
                case 0x18:
                    new CryptoFrame(tlsState).parse(buffer, log);
                    break;
                case 0x1a:
                    if (quicVersion.atLeast(Version.IETF_draft_15))
                        new AckFrame().parse(buffer, log);
                    else
                        throw new NotYetImplementedException();
                    break;
                case 0x1b:
                    if (quicVersion.atLeast(Version.IETF_draft_15))
                        new AckFrame().parse(buffer, log);
                    else
                        throw new NotYetImplementedException();
                    break;
                default:
                    throw new NotYetImplementedException();
            }
        }
    }

}
