package net.luminis.quic;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;


class PaddingTest {

    @Test
    void testPaddingFollowedByOtherFrame() {
        byte[] data = new byte[18];
        data[17] = 0x01;
        Padding padding = new Padding().parse(ByteBuffer.wrap(data), Mockito.mock(Logger.class));

        assertThat(padding.length).isEqualTo(17);
    }

    @Test
    void testPaddingUntilEndOfBuffer() {
        ByteBuffer zeroes = ByteBuffer.wrap(new byte[56]);
        Padding padding = new Padding().parse(zeroes, Mockito.mock(Logger.class));

        assertThat(padding.length).isEqualTo(56);
    }
}