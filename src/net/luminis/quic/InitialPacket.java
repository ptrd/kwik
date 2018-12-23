package net.luminis.quic;

import net.luminis.tls.TlsState;

import java.nio.ByteBuffer;

public class InitialPacket extends LongHeaderPacket {

    public InitialPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, int packetNumber, QuicFrame payload, ConnectionSecrets connectionSecrets) {
        super(quicVersion, sourceConnectionId, destConnectionId, packetNumber, payload.getBytes(), connectionSecrets);
    }

    public InitialPacket(Version quicVersion, QuicConnection connection, TlsState tlsState, ConnectionSecrets connectionSecrets) {
        super(quicVersion, connection, tlsState, connectionSecrets);
    }

    protected byte getPacketType() {
        return (byte) 0xff;
    }

    protected void generateAdditionalFields() {
        // Token length (variable-length integer)
        packetBuffer.put((byte) 0x00);
    }

    @Override
    protected EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.Initial;
    }

    @Override
    protected void checkPacketType(byte type) {
        if (type != (byte) 0xff) {
            // Programming error: this method shouldn't have been called if packet is not Initial
            throw new RuntimeException();
        }
    }

    @Override
    protected void parseAdditionalFields(ByteBuffer buffer) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.5:
        // "An Initial packet (shown in Figure 13) has two additional header
        // fields that are added to the Long Header before the Length field."
        int tokenLength = buffer.get();
        if (tokenLength > 0) {
            buffer.position(buffer.position() + tokenLength);
        }
    }

}
