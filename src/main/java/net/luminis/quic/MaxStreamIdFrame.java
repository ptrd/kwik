package net.luminis.quic;

import java.nio.ByteBuffer;

public class MaxStreamIdFrame extends QuicFrame {

    private int maxStreamId;

    public MaxStreamIdFrame parse(ByteBuffer buffer, Logger log) {
        if (buffer.get() != 0x06) {
            throw new RuntimeException();  // Would be a programming error.
        }

        maxStreamId = QuicPacket.parseVariableLengthInteger(buffer);

        return this;
    }

    @Override
    public String toString() {
        return "MaxStreamIdFrame[" + maxStreamId + "]";
    }

    @Override
    byte[] getBytes() {
        return new byte[0];
    }

}
