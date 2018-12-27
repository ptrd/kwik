package net.luminis.quic;

import java.nio.ByteBuffer;
import java.util.stream.Stream;

public class StreamFrame extends QuicFrame {

    enum StreamType {
        ClientInitiatedBidirectional(0, "CIB"),
        ServerInitiatedBidirectional(1, "SIB"),
        ClientInitiatedUnidirectional(2, "CIU"),
        ServerInitiatedUnidirectional(3, "SIU"),
        ;

        public final int value;
        public final String abbrev;

        StreamType(int value, String abbrev) {
            this.value = value;
            this.abbrev = abbrev;
        }
    }

    private StreamType streamType;
    private int length;
    private int streamId;
    private int offset;

    @Override
    byte[] getBytes() {
        return new byte[0];
    }

    public StreamFrame parse(ByteBuffer buffer, Logger log) {
        int frameType = buffer.get();
        boolean withOffset = ((frameType & 0x04) == 0x04);
        boolean withLength = ((frameType & 0x02) == 0x02);
        boolean isFinal = ((frameType & 0x01) == 0x01);

        streamId = QuicPacket.parseVariableLengthInteger(buffer);
        streamType = Stream.of(StreamType.values()).filter(t -> t.value == (frameType & 0x03)).findFirst().get();

        if (withOffset) {
            offset = QuicPacket.parseVariableLengthInteger(buffer);
        }
        if (withLength) {
            length = QuicPacket.parseVariableLengthInteger(buffer);
        }

        byte[] streamData;
        if (length > 0) {
            length = buffer.limit() - buffer.position();
        }
        streamData = new byte[length];
        buffer.get(streamData);

        return this;
    }

    @Override
    public String toString() {
        return "StreamFrame[" + streamId + "(" + streamType.abbrev + ")" + "," + offset + "," + length + "]";
    }
}
