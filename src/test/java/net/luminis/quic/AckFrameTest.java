package net.luminis.quic;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class AckFrameTest {

    @Test
    void testParse() {
        byte[] data = new byte[] { 0x0d, 0x00, 0x00, 0x00, 0x00 };

        AckFrame ack = new AckFrame().parse(ByteBuffer.wrap(data), Mockito.mock(Logger.class));
        assertThat(ack.toString()).isEqualTo("AckFrame[0]");
    }
}