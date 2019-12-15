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

import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;
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
    void testParseStreamWithoutOffsetAndLengthByte() {
        byte[] raw = new byte[] { 0x08, 0x02, 48, 49, 50, 51, 52 };
        StreamFrame frame = new StreamFrame().parse(ByteBuffer.wrap(raw), Mockito.mock(Logger.class));

        assertThat(frame.getStreamId()).isEqualTo(2);
        assertThat(frame.getOffset()).isEqualTo(0);
        assertThat(frame.getLength()).isEqualTo(5);
        assertThat(frame.getStreamData()).isEqualTo("01234".getBytes());
        assertThat(frame.isFinal()).isEqualTo(false);
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