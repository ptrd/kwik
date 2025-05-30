/*
 * Copyright © 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.impl.Role;
import tech.kwik.core.log.Logger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class StreamInputStreamImplTest {

    private StreamInputStreamImpl streamInputStream;

    @BeforeEach
    void setUp() {
        StreamManager streamManager = mock(StreamManager.class);

        QuicStreamImpl quicStream = new QuicStreamImpl(0, Role.Client, mock(QuicConnectionImpl.class), streamManager, mock(FlowControl.class));
        streamInputStream = new StreamInputStreamImpl(quicStream, 10_000L, mock(Logger.class));
    }

    @Test
    void whenFirstStreamFrameAddIncrEqualsUpToOffset() throws Exception {
        // When
        long incr = streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[876], false));

        // Then
        assertThat(incr).isEqualTo(876);
    }

    @Test
    void whenMultipleStreamFramesAddedIncrEqualsNetIncrement() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[700], false));

        // When
        long incr = streamInputStream.addDataFrom(new StreamFrame(0, 600, new byte[250], false));

        // Then
        assertThat(incr).isEqualTo(150);
    }

    @Test
    void whenMultipleStreamFramesAddedWithGapInBetweeIncrEqualsUpToOffsetDiff() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[500], false));

        // When
        long incr = streamInputStream.addDataFrom(new StreamFrame(0, 800, new byte[250], false));

        // Then
        assertThat(incr).isEqualTo(550);
    }
}
