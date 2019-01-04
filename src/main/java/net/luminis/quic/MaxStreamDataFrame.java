package net.luminis.quic;

import java.nio.ByteBuffer;

// https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.10
public class MaxStreamDataFrame extends QuicFrame {

    private int streamId;
    private int maxData;

    public MaxStreamDataFrame parse(ByteBuffer buffer, Logger log) {
        if (buffer.get() != 0x05) {
            throw new RuntimeException();  // Would be a programming error.
        }

        streamId = QuicPacket.parseVariableLengthInteger(buffer);
        maxData = QuicPacket.parseVariableLengthInteger(buffer);

        return this;
    }

    @Override
    public String toString() {
        return "MaxStreamDataFrame[" + streamId + ":" + maxData + "]";
    }

    @Override
    byte[] getBytes() {
        return new byte[0];
    }
}
