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

import tech.kwik.core.log.Logger;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class PaddingTest {

    @Test
    void testParsePaddingAtEndOfBuffer() {
        byte[] data = new byte[1221];
        ByteBuffer buffer = ByteBuffer.wrap(data);
        // Simulate already 21 packet bytes (frames) are parsed
        buffer.position(21);
        Padding padding = new Padding().parse(buffer, mock(Logger.class));

        assertThat(padding.getLength()).isEqualTo(1200);
        assertThat(buffer.remaining()).isEqualTo(0);
    }

    @Test
    void testParsePaddingAtStartOfBuffer() {
        byte[] data = new byte[1200];
        ByteBuffer buffer = ByteBuffer.wrap(data);
        // Simulate other frames are starting at position 1000
        data[1000] = 1;
        Padding padding = new Padding().parse(buffer, mock(Logger.class));

        assertThat(padding.getLength()).isEqualTo(1000);
        assertThat(buffer.remaining()).isEqualTo(200);
        assertThat(buffer.get()).isEqualTo((byte) 1);
    }

    @Test
    void testParsePaddingInMiddleOfBuffer() {
        byte[] data = new byte[1200];
        ByteBuffer buffer = ByteBuffer.wrap(data);
        // Simulate already 21 packet bytes (frames) are parsed
        buffer.position(20);
        // Simulate other frames are starting at position 1000
        data[1000] = 1;
        Padding padding = new Padding().parse(buffer, mock(Logger.class));

        assertThat(padding.getLength()).isEqualTo(1000 - 20);
        assertThat(buffer.remaining()).isEqualTo(200);
        assertThat(buffer.get()).isEqualTo((byte) 1);
    }

    @Test
    void testParsePaddingFollowedBySingleBytePingFrame() {
        byte[] data = new byte[1200];
        data[1199] = 1;
        ByteBuffer buffer = ByteBuffer.wrap(data);
        Padding padding = new Padding().parse(buffer, mock(Logger.class));

        assertThat(padding.getLength()).isEqualTo(1199);
        assertThat(buffer.remaining()).isEqualTo(1);
        assertThat(buffer.get()).isEqualTo((byte) 1);
    }

    @Test
    void testParseMinimalPadding() {
        byte[] data = new byte[1];
        data[0] = 0;
        ByteBuffer buffer = ByteBuffer.wrap(data);
        Padding padding = new Padding().parse(buffer, mock(Logger.class));

        assertThat(padding.getLength()).isEqualTo(1);
        assertThat(buffer.remaining()).isEqualTo(0);
    }

    @Test
    void testGetFrameLength() {
        // Given
        var frame = new Padding(80);

        // When
        ByteBuffer buffer = ByteBuffer.allocate(100);
        frame.serialize(buffer);
        buffer.flip();

        // Then
        assertThat(frame.getFrameLength()).isEqualTo(buffer.remaining());
    }


}