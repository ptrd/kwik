package net.luminis.quic;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;


class StreamFrameTest {

    @Test
    void testStreamFrameParsing() {
        byte[] data = generateByteArray(10);
        StreamFrame frame = new StreamFrame(16, 0, data, true);
        // Generate frame bytes and parse
        frame = new StreamFrame().parse(ByteBuffer.wrap(frame.getBytes()), Mockito.mock(Logger.class));
        assertThat(frame.getStreamId()).isEqualTo(16);
        assertThat(frame.getOffset()).isEqualTo(0);
        assertThat(frame.getStreamData()).isEqualTo("0123456789".getBytes());
        assertThat(frame.getLength()).isEqualTo(10);
        assertThat(frame.isFinal()).isEqualTo(true);
    }

    @Test
    void testStreamFrameByteArraySlicing() {
        byte[] data = generateByteArray(26);
        StreamFrame frame = new StreamFrame(0, 0, data, 3, 5, true);
        // Generate frame bytes and parse to get access to copied data bytes.
        frame = new StreamFrame().parse(ByteBuffer.wrap(frame.getBytes()), Mockito.mock(Logger.class));
        assertThat(frame.getStreamData()).isEqualTo("34567".getBytes());
    }

    private byte[] generateByteArray(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            // Generate 0-9 sequence; ASCII 0 = 48
            data[i] = (byte) (48 + (i % 10));
        }
        return data;
    }
}