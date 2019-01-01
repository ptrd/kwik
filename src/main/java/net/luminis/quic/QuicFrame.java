package net.luminis.quic;

import java.nio.ByteBuffer;

public abstract class QuicFrame {

    abstract byte[] getBytes();

    byte[] encodeVariableLengthInteger(int value) {
        if (value <= 63)
            return new byte[] { (byte) value };
        else if (value <= 16383) {
            ByteBuffer buffer = ByteBuffer.allocate(2);
            buffer.putShort((short) value);
            byte[] bytes = buffer.array();
            bytes[0] = (byte) (bytes[0] | (byte) 0x40);
            return bytes;
        }
        else {
            // TODO
            throw new RuntimeException("NIY");
        }
    }


}
