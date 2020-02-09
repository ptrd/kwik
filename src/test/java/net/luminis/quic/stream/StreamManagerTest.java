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
package net.luminis.quic.stream;

import net.luminis.quic.PnSpace;
import net.luminis.quic.QuicConnectionImpl;
import net.luminis.quic.frame.MaxStreamsFrame;
import net.luminis.quic.log.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class StreamManagerTest {

    private StreamManager streamManager;

    @BeforeEach
    void init() {
        streamManager = new StreamManager(mock(QuicConnectionImpl.class), mock(Logger.class));
    }

    @Test
    void canCreateBidirectionalStreamWhenMaxStreamsNotReached() {
        // Given
        streamManager.setInitialMaxStreamsBidi(3);

        // When
        QuicStream stream1 = streamManager.createStream(true);
        QuicStream stream2 = streamManager.createStream(true);
        QuicStream stream3 = streamManager.createStream(true);

        // Then
        assertThat(stream1).isNotNull();
        assertThat(stream2).isNotNull();
        assertThat(stream3).isNotNull();
    }

    @Test
    void canCreateUnirectionalStreamWhenMaxStreamsNotReached() {
        // Given
        streamManager.setInitialMaxStreamsUni(3);

        // When
        QuicStream stream1 = streamManager.createStream(false);
        QuicStream stream2 = streamManager.createStream(false);
        QuicStream stream3 = streamManager.createStream(false);

        // Then
        assertThat(stream1).isNotNull();
        assertThat(stream2).isNotNull();
        assertThat(stream3).isNotNull();
    }

    @Test
    void cannotCreateBidirectionalStreamWhenMaxStreamsReached() {
        // Given
        streamManager.setInitialMaxStreamsBidi(1);

        // When
        QuicStream stream1 = streamManager.createStream(true);
        QuicStream stream2 = streamManager.createStream(true);

        // Then
        assertThat(stream1).isNotNull();
        assertThat(stream2).isNull();
    }

    @Test
    void cannotCreateUnirectionalStreamWhenMaxStreamsReached() {
        // Given
        streamManager.setInitialMaxStreamsUni(1);

        // When
        QuicStream stream1 = streamManager.createStream(false);
        QuicStream stream2 = streamManager.createStream(false);

        // Then
        assertThat(stream1).isNotNull();
        assertThat(stream2).isNull();
    }

    @Test
    void canCreateBidirectionalStreamWhenMaxStreamsIsIncreased() {
        // Given
        streamManager.setInitialMaxStreamsBidi(1);
        QuicStream stream1 = streamManager.createStream(true);
        QuicStream stream2a = streamManager.createStream(true);

        // When
        streamManager.process(new MaxStreamsFrame(8, true), PnSpace.App, Instant.now());
        QuicStream stream2b = streamManager.createStream(true);

        // Then
        assertThat(stream1).isNotNull();
        assertThat(stream2a).isNull();
        assertThat(stream2b).isNotNull();
    }

    @Test
    void canCreateUndirectionalStreamWhenMaxStreamsIsIncreased() {
        // Given
        streamManager.setInitialMaxStreamsUni(1);
        QuicStream stream1 = streamManager.createStream(false);
        QuicStream stream2a = streamManager.createStream(false);

        // When
        streamManager.process(new MaxStreamsFrame(8, false), PnSpace.App, Instant.now());
        QuicStream stream2b = streamManager.createStream(false);

        // Then
        assertThat(stream1).isNotNull();
        assertThat(stream2a).isNull();
        assertThat(stream2b).isNotNull();
    }

    @Test
    void maxBidiStreamsCanNeverDecrease() {
        // Given
        streamManager.setInitialMaxStreamsBidi(1);
        streamManager.process(new MaxStreamsFrame(8, true), PnSpace.App, Instant.now());

        // When
        streamManager.process(new MaxStreamsFrame(5, true), PnSpace.App, Instant.now());

        // Then
        assertThat(streamManager.getMaxBidirectionalStreams()).isGreaterThanOrEqualTo(8);
    }

    @Test
    void maxUniStreamsCanNeverDecrease() {
        // Given
        streamManager.setInitialMaxStreamsUni(1);
        streamManager.process(new MaxStreamsFrame(8, false), PnSpace.App, Instant.now());

        // When
        streamManager.process(new MaxStreamsFrame(5, false), PnSpace.App, Instant.now());

        // Then
        assertThat(streamManager.getMaxUnirectionalStreams()).isGreaterThanOrEqualTo(8);
    }

    @Test
    void settingInitialMaxBidiStreamsCanOnlyBeDoneOnce() {
        // Given
        streamManager.setInitialMaxStreamsBidi(2);

        assertThatThrownBy(
                // When
                () -> streamManager.setInitialMaxStreamsBidi(3)
        )
                // Then
                .isInstanceOf(IllegalStateException.class);

        assertThat(streamManager.getMaxBidirectionalStreams()).isEqualTo(2);
    }

    @Test
    void settingInitialMaxUniStreamsCanOnlyBeDoneOnce() {
        // Given
        streamManager.setInitialMaxStreamsUni(1);

        assertThatThrownBy(
                // When
                () -> streamManager.setInitialMaxStreamsUni(3)
        )
                // Then
                .isInstanceOf(IllegalStateException.class);

        assertThat(streamManager.getMaxUnirectionalStreams()).isEqualTo(1);
    }

}