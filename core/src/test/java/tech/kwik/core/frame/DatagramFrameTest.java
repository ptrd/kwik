/*
 * Copyright © 2024, 2025 Peter Doornbosch
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

import java.nio.ByteBuffer;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class DatagramFrameTest {

    @Test
    void parseDatagramFrameWithLengthField() throws Exception {
        // Given
        byte[] data = new byte[] { 0x31, 0x04, 0x71, 0x75, 0x69, 0x63 };
        DatagramFrame datagramFrame = new DatagramFrame();

        // When
        datagramFrame.parse(ByteBuffer.wrap(data), null);

        // Then
        assertThat(datagramFrame.getData()).isEqualTo(new byte[] { 0x71, 0x75, 0x69, 0x63 });
    }

    @Test
    void parseDatagramFrameWithoutLengthField() throws Exception {
        // Given
        byte[] data = new byte[] { 0x30, 0x71, 0x75, 0x69, 0x63 };
        DatagramFrame datagramFrame = new DatagramFrame();

        // When
        datagramFrame.parse(ByteBuffer.wrap(data), null);

        // Then
        assertThat(datagramFrame.getData()).isEqualTo(new byte[] { 0x71, 0x75, 0x69, 0x63 });
    }

    @Test
    void parseZeroLenthDatagramWithLengthField() throws Exception {
        // Given
        byte[] data = new byte[] { 0x31, 0x00 };
        DatagramFrame datagramFrame = new DatagramFrame();

        // When
        datagramFrame.parse(ByteBuffer.wrap(data), null);

        // Then
        assertThat(datagramFrame.getData())
                .isNotNull()
                .isEmpty();
    }

    @Test
    void parseZeroLenthDatagramWithoutLengthField() throws Exception {
        // Given
        byte[] data = new byte[] { 0x30 };
        DatagramFrame datagramFrame = new DatagramFrame();

        // When
        datagramFrame.parse(ByteBuffer.wrap(data), null);

        // Then
        assertThat(datagramFrame.getData())
                .isNotNull()
                .isEmpty();
    }
}