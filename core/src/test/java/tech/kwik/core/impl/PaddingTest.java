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
package tech.kwik.core.impl;

import tech.kwik.core.frame.Padding;
import tech.kwik.core.log.Logger;
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

        assertThat(padding.getLength()).isEqualTo(17);
    }

    @Test
    void testPaddingUntilEndOfBuffer() {
        ByteBuffer zeroes = ByteBuffer.wrap(new byte[56]);
        Padding padding = new Padding().parse(zeroes, Mockito.mock(Logger.class));

        assertThat(padding.getLength()).isEqualTo(56);
    }
}