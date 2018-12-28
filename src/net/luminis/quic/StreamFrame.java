package net.luminis.quic;

import java.nio.ByteBuffer;
import java.util.stream.Stream;

import static net.luminis.quic.StreamType.ClientInitiatedBidirectional;

public class StreamFrame extends QuicFrame {

    private StreamType streamType;
    private int length;
    private int streamId;
    private int offset;
    private byte[] frameData;

    public StreamFrame() {
    }

    public StreamFrame(int streamId, String applicationData) {
        streamType = ClientInitiatedBidirectional;

        ByteBuffer buffer = ByteBuffer.allocate(1 + 3 * 4 + applicationData.getBytes().length);
        byte frameType = 0x10 | 0x04 | 0x02 | 0x01;  // OFF-bit, LEN-bit, FIN-bit
        buffer.put(frameType);
        buffer.put(encodeVariableLengthInteger(streamId));
        buffer.put(encodeVariableLengthInteger(0));  // offset
        buffer.put(encodeVariableLengthInteger(applicationData.getBytes().length));  // length
        buffer.put(applicationData.getBytes());

        frameData = new byte[buffer.position()];
        buffer.rewind();
        buffer.get(frameData);
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
        log.debug("Stream data", streamData);

        return this;
    }

    @Override
    byte[] getBytes() {
        return frameData;
    }

    @Override
    public String toString() {
        return "StreamFrame[" + streamId + "(" + streamType.abbrev + ")" + "," + offset + "," + length + "]";
    }
}
