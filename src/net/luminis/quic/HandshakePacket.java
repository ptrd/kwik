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
