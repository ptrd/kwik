package net.luminis.quic;

import java.nio.ByteBuffer;

public class AckFrame extends QuicFrame {

    private byte[] frameBytes;
    private int largestAcknowledged;

    public AckFrame() {
    }

    public AckFrame(Version quicVersion, int packetNumber) {
        largestAcknowledged = packetNumber;
        ByteBuffer buffer = ByteBuffer.allocate(100);

        if (quicVersion.equals(Version.IETF_draft_14)) {
            buffer.put((byte) 0x0d);
        }
        else if (quicVersion.atLeast(Version.IETF_draft_15)) {
            buffer.put((byte) 0x1a);
        }

        buffer.put(encodeVariableLengthInteger(packetNumber));
        buffer.put(encodeVariableLengthInteger(0));
        buffer.put(encodeVariableLengthInteger(0));
        buffer.put(encodeVariableLengthInteger(0));

        frameBytes = new byte[buffer.position()];
        buffer.flip();
        buffer.get(frameBytes);
    }

    public AckFrame parse(ByteBuffer buffer, Logger log) {
        log.debug("Parsing AckFrame");

        largestAcknowledged = QuicPacket.parseVariableLengthInteger(buffer);
        int ackDelay = QuicPacket.parseVariableLengthInteger(buffer);
        int ackBlockCount = QuicPacket.parseVariableLengthInteger(buffer);
        int acknowledgedPacketsCount = QuicPacket.parseVariableLengthInteger(buffer);

        // For the time being, we only parse simple Ack frames, without Additional Ack Block's
        if (ackBlockCount > 0)
            throw new NotYetImplementedException();

        return this;
    }

    @Override
    public String toString() {
        return "AckFrame[" + largestAcknowledged + "]";
    }

    @Override
    byte[] getBytes() {
        return frameBytes;
    }
}
