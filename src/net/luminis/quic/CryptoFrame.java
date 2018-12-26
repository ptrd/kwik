package net.luminis.quic;

import net.luminis.tls.TlsState;

import java.nio.ByteBuffer;

public class CryptoFrame extends QuicFrame {

    private TlsState tlsState;
    private ConnectionSecrets connectionSecrets;

    private int offset;
    private int length;
    private byte[] cryptoData;

    public CryptoFrame(byte[] payload) {
        offset = 0;
        cryptoData = payload;
        length = payload.length;
        ByteBuffer frameBuffer = ByteBuffer.allocate(3 * 4 + payload.length);
        frameBuffer.put(encodeVariableLengthInteger(0x18));
        frameBuffer.put(encodeVariableLengthInteger(offset));
        frameBuffer.put(encodeVariableLengthInteger(payload.length));
        frameBuffer.put(payload);

        cryptoData = new byte[frameBuffer.position()];
        frameBuffer.rewind();
        frameBuffer.get(cryptoData);
    }

    public CryptoFrame(ConnectionSecrets connectionSecrets, TlsState tlsState) {
        this.connectionSecrets = connectionSecrets;
        this.tlsState = tlsState;
    }

    public CryptoFrame parse(ByteBuffer buffer, Logger log) {
        log.debug("Parsing Crypto frame");

        offset = QuicPacket.parseVariableLengthInteger(buffer);
        length = QuicPacket.parseVariableLengthInteger(buffer);

        cryptoData = new byte[length];
        buffer.get(cryptoData);
        log.debug("Crypto data [" + offset + "," + length + "]", cryptoData);

        return this;
    }

    @Override
    public String toString() {
        return "CryptoFrame[" + offset + "," + length + "]";
    }

    public byte[] getBytes() {
        return cryptoData;
    }

    public byte[] getCryptoData() {
        return cryptoData;
    }

    public int getOffset() {
        return offset;
    }

    public int getLength() {
        return length;
    }
}
