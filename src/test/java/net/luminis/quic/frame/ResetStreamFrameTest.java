/*
 * Copyright © 2021, 2022 Peter Doornbosch
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


class ResetStreamFrameTest {

    @Test
    void getMaximumFrameSize() {
        long fourGig = 4L * 1024 * 1024 * 1024;
        assertThat(fourGig).isGreaterThan(Integer.MAX_VALUE);

        int streamId = 66;
        int errorCode = 666;
        int maximumFrameSize = ResetStreamFrame.getMaximumFrameSize(streamId, errorCode);
        ResetStreamFrame resetStreamFrame = new ResetStreamFrame(streamId, errorCode, fourGig);

        assertThat(resetStreamFrame.getFrameLength()).isLessThanOrEqualTo(maximumFrameSize);
    }

    @Test
    void testGetFrameLength() {
        // Given
        var resetStreamFrame = new ResetStreamFrame(8, 592, 65_000);

        // When
        ByteBuffer buffer = ByteBuffer.allocate(100);
        resetStreamFrame.serialize(buffer);
        buffer.flip();

        // Then
        assertThat(resetStreamFrame.getFrameLength()).isEqualTo(buffer.remaining());
    }
}