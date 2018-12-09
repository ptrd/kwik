package net.luminis.quic;

import java.nio.ByteBuffer;

public class AckFrame {

    public void parse(ByteBuffer buffer, Logger log) {
        log.debug("Parsing AckFrame");

        int largestAcknowledged = QuicPacket.parseVariableLengthInteger(buffer);
        int ackDelay = QuicPacket.parseVariableLengthInteger(buffer);
        int ackBlockCount = QuicPacket.parseVariableLengthInteger(buffer);
        int acknowledgedPacketsCount = QuicPacket.parseVariableLengthInteger(buffer);

        // For the time being, we only parse simple Ack frames, without Additional Ack Block's
        if (ackBlockCount > 0)
            throw new NotYetImplementedException();
    }

}
