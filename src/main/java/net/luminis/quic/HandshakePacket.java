package net.luminis.quic;

import net.luminis.tls.TlsState;

import java.nio.ByteBuffer;

public class HandshakePacket extends LongHeaderPacket {

    public HandshakePacket(Version quicVersion, QuicConnection connection, ConnectionSecrets connectionSecrets, TlsState tlsState) {
        super(quicVersion, connection, tlsState, connectionSecrets);
    }

    public HandshakePacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, int packetNumber, QuicFrame payload, ConnectionSecrets connectionSecrets) {
        super(quicVersion, sourceConnectionId, destConnectionId, packetNumber, payload, connectionSecrets);
    }

    protected byte getPacketType() {
        return (byte) 0xfd;
    }

    @Override
    protected void generateAdditionalFields() {
    }

    @Override
    protected EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.Handshake;
    }

    @Override
    public void accept(PacketProcessor processor) {
        processor.process(this);
    }

    @Override
    protected void checkPacketType(byte type) {
        if (type != (byte) 0xfd) {
            // Programming error: this method shouldn't have been called if packet is not Initial
            throw new RuntimeException();
        }
    }

    @Override
    protected void parseAdditionalFields(ByteBuffer buffer) {
    }


}
