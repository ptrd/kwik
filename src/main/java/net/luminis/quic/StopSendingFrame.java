package net.luminis.quic;

import java.nio.ByteBuffer;

// https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-19.5
public class StopSendingFrame extends QuicFrame {

    private int streamId;
    private int errorCode;

    public StopSendingFrame(Version quicVersion) {
    }

    @Override
    byte[] getBytes() {
        return new byte[0];
    }

    public StopSendingFrame parse(ByteBuffer buffer, Logger log) {
        if ((buffer.get() & 0xff) != 0x0c) {
            throw new RuntimeException();  // Programming error
        }

        streamId = QuicPacket.parseVariableLengthInteger(buffer);
        errorCode = buffer.getShort() & 0xffff;

        return this;
    }

    @Override
    public String toString() {
        return "StopSendingFrame[" + streamId + ":" + errorCode + "]";
    }

}
