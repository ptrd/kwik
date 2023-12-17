/*
 * Copyright © 2023 Peter Doornbosch
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
package net.luminis.quic.stream;

import net.luminis.quic.ConnectionConfig;
import net.luminis.quic.core.QuicConnectionImpl;
import net.luminis.quic.core.Role;
import net.luminis.quic.frame.StreamFrame;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class StreamInputStreamTest {

    private StreamInputStream streamInputStream;

    @BeforeEach
    void setUp() {
        ConnectionConfig config = mock(ConnectionConfig.class);
        when(config.maxBidirectionalStreamBufferSize()).thenReturn(10_000L);
        when(config.maxUnidirectionalStreamBufferSize()).thenReturn(10_000L);
        StreamManager streamManager = mock(StreamManager.class);
        when(streamManager.getConnectionConfig()).thenReturn(config);

        QuicStreamImpl quicStream = new QuicStreamImpl(0, Role.Client, mock(QuicConnectionImpl.class), streamManager, mock(FlowControl.class));
        streamInputStream = new StreamInputStream(quicStream, 10_000L);
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
