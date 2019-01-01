package net.luminis.quic;

import java.nio.ByteBuffer;

public class NewConnectionIdFrame extends QuicFrame {

    private Version quicVersion;
    private int sequence;

    public NewConnectionIdFrame(Version quicVersion) {
        this.quicVersion = quicVersion;
    }

    @Override
    byte[] getBytes() {
        return new byte[0];
    }

    public NewConnectionIdFrame parse(ByteBuffer buffer, Logger log) {
        buffer.get();

        if (quicVersion.equals(Version.IETF_draft_14)) {
            sequence = QuicPacket.parseVariableLengthInteger(buffer);
            int connectionIdLength = buffer.get();
            byte[] connectionId = new byte[connectionIdLength];
            buffer.get(connectionId);
        }
        else if (quicVersion.atLeast(Version.IETF_draft_15)) {
            int connectionIdLength = buffer.get();
            sequence = QuicPacket.parseVariableLengthInteger(buffer);
            byte[] connectionId = new byte[connectionIdLength];
            buffer.get(connectionId);
        }

        byte[] statelessResetToken = new byte[128 / 8];
        buffer.get(statelessResetToken);

        return this;
    }

    @Override
    public String toString() {
        return "NewConnectionIdFrame[" + sequence + "]";
    }
}
