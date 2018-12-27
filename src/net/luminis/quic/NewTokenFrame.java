package net.luminis.quic;

import net.luminis.tls.ByteUtils;

import java.nio.ByteBuffer;

public class NewTokenFrame extends QuicFrame {

    private byte[] newToken;

    @Override
    byte[] getBytes() {
        return new byte[0];
    }

    public NewTokenFrame parse(ByteBuffer buffer, Logger log) {
        if ((buffer.get() & 0xff) != 0x19) {
            throw new RuntimeException();  // Programming error
        }

        int tokenLength = QuicPacket.parseVariableLengthInteger(buffer);
        newToken = new byte[tokenLength];
        buffer.get(newToken);

        log.debug("Got New Token: ", newToken);

        return this;
    }

    @Override
    public String toString() {
        return "NewTokenFrame[" + ByteUtils.bytesToHex(newToken) + "]";
    }
}
