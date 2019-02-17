/*
 * Copyright © 2019 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
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
        assertThat(ack.toString()).contains("8,7,2,1");
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