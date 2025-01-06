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

import tech.kwik.core.impl.Version;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;


class RetireConnectionIdFrameTest {

    @Test
    void testGetFrameLength() {
        // Given
        var retireConnectionIdFrame = new RetireConnectionIdFrame(Version.getDefault(), 28);

        // When
        ByteBuffer buffer = ByteBuffer.allocate(100);
        retireConnectionIdFrame.serialize(buffer);
        buffer.flip();

        // Then
        assertThat(retireConnectionIdFrame.getFrameLength()).isEqualTo(buffer.remaining());
    }

}