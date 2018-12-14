package net.luminis.quic;

import net.luminis.tls.ServerHello;
import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.TlsState;

import java.nio.ByteBuffer;

public class CryptoFrame {

    private final TlsState tlsState;

    public CryptoFrame(TlsState tlsState) {

        this.tlsState = tlsState;
    }

    public void parse(ByteBuffer buffer, Logger log) {
        log.debug("Parsing Crypto frame");

        int offset = QuicPacket.parseVariableLengthInteger(buffer);
        int length = QuicPacket.parseVariableLengthInteger(buffer);

        byte[] cryptoData = new byte[length];
        buffer.get(cryptoData);
        log.debug("Crypto data", cryptoData);

        int handshakeType = cryptoData[0];
        if (handshakeType == TlsConstants.HandshakeType.server_hello.value) {
            log.debug("Crypto frame contains Server Hello");
            try {
                new ServerHello().parse(ByteBuffer.wrap(cryptoData), length, tlsState);
            } catch (TlsProtocolException e) {
                throw new ProtocolError("tls error", e);
            }
        }
        else {
            throw new ProtocolError("Unknown handshake type in Crypto Frame");
        }
    }
}
