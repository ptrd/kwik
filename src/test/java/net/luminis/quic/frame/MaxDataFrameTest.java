/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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
package net.luminis.quic.frame;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;


class MaxDataFrameTest extends FrameTest {

    @Test
    void testEncodeSingleByteValue() {
        byte[] bytes = getBytes(new MaxDataFrame(60));

        assertThat(bytes).isEqualTo(new byte[] { 0x10, 0x3c });
    }

    @Test
    void testEncodeTwoBytesValue() {
        byte[] bytes = getBytes(new MaxDataFrame(16000));

        assertThat(bytes).isEqualTo(new byte[] { 0x10, 0x7e, (byte) 0x80 });
    }

    @Test
    void testEncodeFourBytesValue() {
        byte[] bytes = getBytes(new MaxDataFrame(65535));

        assertThat(bytes).isEqualTo(new byte[] { 0x10, (byte) 0x80, 0x00, (byte) 0xff, (byte) 0xff });
    }
    @Test
    void testEncodeEightBytesValue() {
        byte[] bytes = getBytes(new MaxDataFrame(2_000_000_000));

        assertThat(bytes).isEqualTo(new byte[] { 0x10, (byte) 0xc0, (byte) 0x00, (byte) 0x00, (byte) 0x00, 0x77, 0x35, (byte) 0x94, 0x00 });
    }

    @Test
    void testGetFrameLength() {
        // Given
        MaxDataFrame maxDataFrame = new MaxDataFrame(16000);

        // When
        ByteBuffer buffer = ByteBuffer.allocate(100);
        maxDataFrame.serialize(buffer);
        buffer.flip();

        // Then
        assertThat(maxDataFrame.getFrameLength()).isEqualTo(buffer.remaining());
    }
}
