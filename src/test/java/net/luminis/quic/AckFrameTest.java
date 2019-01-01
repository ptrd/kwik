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
        assertThat(ack.getLargestAcknowledged()).isEqualTo(0);
        assertThat(ack.getAckDelay()).isEqualTo(0);
        assertThat(ack.getAckedPacketNumbers()).containsOnly(0);
    }

    @Test
    void testParseAckRangeWithSingleGap() {
        //                         ackframe   largest  delay ack-block-count #acked-below largest gap (size) #acked-below
        byte[] data = new byte[] { 0x0d,      0x02,    0x00, 0x01,           0x00,                0x00,      0x00 };

        AckFrame ack = new AckFrame().parse(ByteBuffer.wrap(data), Mockito.mock(Logger.class));
        assertThat(ack.getLargestAcknowledged()).isEqualTo(2);
        assertThat(ack.getAckDelay()).isEqualTo(0);

        assertThat(ack.getAckedPacketNumbers()).containsOnly(2, 0);
    }

    @Test
    void testParseAckRangeWithLargerGap() {
        //                         ackframe   largest  delay ack-block-count #acked-below largest gap (size) #acked-below
        byte[] data = new byte[] { 0x0d,      0x08,    0x00, 0x01,           0x01,                0x03,      0x01 };

        AckFrame ack = new AckFrame().parse(ByteBuffer.wrap(data), Mockito.mock(Logger.class));
        assertThat(ack.getLargestAcknowledged()).isEqualTo(8);
        assertThat(ack.getAckDelay()).isEqualTo(0);

        assertThat(ack.getAckedPacketNumbers()).containsOnly(8, 7, 2, 1);
        assertThat(ack.toString()).contains("[8,7,2,1]");
    }

    @Test
    void testParseAckRangeWithTwoAckBlocks() {
        //                         ackframe   largest  delay ack-block-count #acked-below largest gap (size) #acked-below gap (size) #acked-below
        byte[] data = new byte[] { 0x0d,      0x0a,    0x00, 0x02,           0x02,                0x01,      0x01,        0x00,      0x02 };

        AckFrame ack = new AckFrame().parse(ByteBuffer.wrap(data), Mockito.mock(Logger.class));
        assertThat(ack.getLargestAcknowledged()).isEqualTo(10);
        assertThat(ack.getAckDelay()).isEqualTo(0);

        assertThat(ack.getAckedPacketNumbers()).containsOnly(10, 9, 8, /* gap: 7, 6 */ 5, 4, /* gap: 3 */ 2, 1, 0);
    }
}