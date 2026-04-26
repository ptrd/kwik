/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
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
package tech.kwik.core.frame;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.log.Logger;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static tech.kwik.core.QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR;


class StreamFrameTest extends FrameTest {

    @Test
    void testStreamFrameParsing() throws Exception {
        byte[] data = generateByteArray(10);
        StreamFrame frame = new StreamFrame(16, 0, data, true);
        // Generate frame bytes and parse
        frame = new StreamFrame().parse(ByteBuffer.wrap(getBytes(frame)), Mockito.mock(Logger.class));
        assertThat(frame.getStreamId()).isEqualTo(16);
        assertThat(frame.getOffset()).isEqualTo(0);
        assertThat(frame.getStreamData()).isEqualTo("0123456789".getBytes());
        assertThat(frame.getLength()).isEqualTo(10);
        assertThat(frame.isFinal()).isEqualTo(true);
    }

    @Test
    void testParseStreamWithoutOffsetAndLengthByte() throws Exception {
        byte[] raw = new byte[] { 0x08, 0x02, 48, 49, 50, 51, 52 };
        StreamFrame frame = new StreamFrame().parse(ByteBuffer.wrap(raw), Mockito.mock(Logger.class));

        assertThat(frame.getStreamId()).isEqualTo(2);
        assertThat(frame.getOffset()).isEqualTo(0);
        assertThat(frame.getLength()).isEqualTo(5);
        assertThat(frame.getStreamData()).isEqualTo("01234".getBytes());
        assertThat(frame.isFinal()).isEqualTo(false);
    }

    @Test
    void testStreamFrameByteArraySlicing() throws Exception {
        byte[] data = generateByteArray(26);
        StreamFrame frame = new StreamFrame(0, 0, data, 3, 5, true);
        // Generate frame bytes and parse to get access to copied data bytes.
        frame = new StreamFrame().parse(ByteBuffer.wrap(getBytes(frame)), Mockito.mock(Logger.class));
        assertThat(frame.getStreamData()).isEqualTo("34567".getBytes());
    }

    @Test
    void parseStreamFrameWithExcessiveDataLengthShouldThrowTransportError() {
        // A length field value exceeding MAX_SUPPORTED_PACKET_SIZE (1500) must be rejected with
        // FRAME_ENCODING_ERROR to prevent OOM. The 2-byte VLI 0x7FFF encodes 16383 (max 2-byte VLI value).
        ByteBuffer buffer = ByteBuffer.wrap(new byte[] {
                0x0A,               // frame type: STREAM with length bit set (bits: 0b00001010)
                0x00,               // stream ID (VLI = 0)
                0x7F, (byte) 0xFF   // length (VLI = 16383, max 2-byte VLI)
        });

        assertThatThrownBy(() -> new StreamFrame().parse(buffer, Mockito.mock(Logger.class)))
                .isInstanceOf(TransportError.class)
                .satisfies(e -> assertThat(((TransportError) e).getErrorCode()).isEqualTo(FRAME_ENCODING_ERROR));
    }

    private byte[] generateByteArray(int size) throws Exception {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            // Generate 0-9 sequence; ASCII 0 = 48
            data[i] = (byte) (48 + (i % 10));
        }
        return data;
    }
}