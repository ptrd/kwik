package net.luminis.quic;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


class MaxStreamDataFrameTest {

     @Test
    void testEncodeSingleByteValue() {
        byte[] bytes = new MaxStreamDataFrame(4, 60).getBytes();

        assertThat(bytes).isEqualTo(new byte[] { 0x11, 0x04, 0x3c });
    }

    @Test
    void testEncodeTwoBytesValue() {
        byte[] bytes = new MaxStreamDataFrame(4, 16000).getBytes();

        assertThat(bytes).isEqualTo(new byte[] { 0x11, 0x04, 0x7e, (byte) 0x80 });
    }

    @Test
    void testEncodeFourBytesValue() {
        byte[] bytes = new MaxStreamDataFrame(4, 65535).getBytes();

        assertThat(bytes).isEqualTo(new byte[] { 0x11, 0x04, (byte) 0x80, 0x00, (byte) 0xff, (byte) 0xff });
    }

    @Test
    void testEncodeEightBytesValue() {
        byte[] bytes = new MaxStreamDataFrame(4, 2_000_000_000).getBytes();

        assertThat(bytes).isEqualTo(new byte[] { 0x11, 0x04, (byte) 0xc0, (byte) 0x00, (byte) 0x00, (byte) 0x00, 0x77, 0x35, (byte) 0x94, 0x00 });
    }

    @Test
    void testLargeStreamId() {
        byte[] bytes = new MaxStreamDataFrame(2_123_456_789, 2_000_000_000).getBytes();

        assertThat(bytes).isEqualTo(new byte[] { 0x11, (byte) 0xc0, 0x00, 0x00, 0x00, 0x7e, (byte) 0x91, 0x61, 0x15, (byte) 0xc0, (byte) 0x00, (byte) 0x00, (byte) 0x00, 0x77, 0x35, (byte) 0x94, 0x00 });
    }
}