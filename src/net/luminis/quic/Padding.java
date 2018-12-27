package net.luminis.quic;

import java.nio.ByteBuffer;

// https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-19.1
// The PADDING frame (type=0x00) has no semantic value.
// A PADDING frame has no content.  That is, a PADDING frame consists of
//   the single octet that identifies the frame as a PADDING frame.
public class Padding extends QuicFrame {

    int length;

    /**
     * Strictly speaking, a padding frame consists of one single byte. For convenience, here all subsequent padding
     * bytes are collected in one padding object.
     * @param buffer
     * @param log
     * @return
     */
    public Padding parse(ByteBuffer buffer, Logger log) {
        while (buffer.get() == 0)
            length++;

        // Set back one position
        buffer.position(buffer.position() - 1);

        return this;
    }

    @Override
    byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public String toString() {
        return "Padding(" + length + ")";
    }
}
