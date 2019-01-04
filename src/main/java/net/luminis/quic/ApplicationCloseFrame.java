package net.luminis.quic;

import java.nio.ByteBuffer;

// https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-19.4
public class ApplicationCloseFrame extends QuicFrame {

    private int errorCode;
    private String reasonPhrase;

    public ApplicationCloseFrame parse(ByteBuffer buffer, Logger log) {
        if (buffer.get() != 0x03) {
            throw new RuntimeException();  // Would be a programming error.
        }

        errorCode = buffer.getShort() & 0xffff;
        int reasonPhraseLength = QuicPacket.parseVariableLengthInteger(buffer);
        if (reasonPhraseLength > 0) {
            byte[] data = new byte[reasonPhraseLength];
            buffer.get(data);
            reasonPhrase = new String(data);
        }
        else {
            reasonPhrase = "";
        }

        return this;
    }

    @Override
    byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public String toString() {
        return "ApplicationCloseFrame[" + errorCode + "/" + reasonPhrase + "]";
    }
}
