/*
 * Copyright © 2020 Peter Doornbosch
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
import net.luminis.quic.Role;
import net.luminis.quic.frame.MaxStreamsFrame;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class StreamManagerTest {

    private StreamManager streamManager;

    @BeforeEach
    void init() {
        streamManager = new StreamManager(mock(QuicConnectionImpl.class), Role.Client, mock(Logger.class));
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
        QuicStream stream1 = streamManager.createStream(true);

        assertThatThrownBy(
                // When
                () -> streamManager.createStream(true, 1, TimeUnit.MILLISECONDS)
                // Then
        ).isInstanceOf(TimeoutException.class);

        assertThat(stream1).isNotNull();
    }

    @Test
    void cannotCreateUnirectionalStreamWhenMaxStreamsReached() {
        // Given
        streamManager.setInitialMaxStreamsUni(1);
        QuicStream stream1 = streamManager.createStream(false);

        assertThatThrownBy(
                // When
                () -> streamManager.createStream(false, 1, TimeUnit.MILLISECONDS)
                // Then
        ).isInstanceOf(TimeoutException.class);

        assertThat(stream1).isNotNull();
    }

    @Test
    void canCreateBidirectionalStreamWhenMaxStreamsIsIncreased() {
        // Given
        streamManager.setInitialMaxStreamsBidi(1);
        QuicStream stream1 = streamManager.createStream(true);

        // When
        streamManager.process(new MaxStreamsFrame(8, true), PnSpace.App, Instant.now());
        QuicStream stream2 = streamManager.createStream(true);

        // Then
        assertThat(stream1).isNotNull();
        assertThat(stream2).isNotNull();
    }

    @Test
    void canCreateUndirectionalStreamWhenMaxStreamsIsIncreased() {
        // Given
        streamManager.setInitialMaxStreamsUni(1);
        QuicStream stream1 = streamManager.createStream(false);

        // When
        streamManager.process(new MaxStreamsFrame(8, false), PnSpace.App, Instant.now());
        QuicStream stream2 = streamManager.createStream(false);

        // Then
        assertThat(stream1).isNotNull();
        assertThat(stream2).isNotNull();
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
    void settingInitialMaxBidiStreamsCanOnlyIncreaseValue() {
        // Given
        streamManager.setInitialMaxStreamsBidi(4);

        // When
        streamManager.setInitialMaxStreamsBidi(3);

        assertThat(streamManager.getMaxBidirectionalStreams()).isEqualTo(4);
    }

    @Test
    void settingInitialMaxUniStreamsCanOnlyIncreaseValue() {
        // Given
        streamManager.setInitialMaxStreamsUni(10);

        // When
        streamManager.setInitialMaxStreamsUni(3);

        assertThat(streamManager.getMaxUnirectionalStreams()).isEqualTo(10);
    }

    @Test
    void blockingCreateBidirectionalStreamContinuesWhenMaxStreamsIsIncreased() throws Exception {
        // Given
        streamManager.setInitialMaxStreamsBidi(1);
        QuicStream firstStream = streamManager.createStream(true);
        assertThat(firstStream).isNotNull();

        AtomicReference<QuicStream> streamReference = new AtomicReference<>();
        new Thread(() -> {
            // Creating the stream should block, because there are not credits at the moment
            QuicStream stream = streamManager.createStream(true);
            streamReference.set(stream);
        }).start();

        Thread.sleep(50);  // Give parallel thread a little time to start, so it blocks before this thread continues
        assertThat(streamReference.get()).isNull();  // This should more or less prove the thread is blocking

        // When
        streamManager.process(new MaxStreamsFrame(2, true), PnSpace.App, Instant.now());
        Thread.sleep(50);  // Give parallel thread a little time to finish
        // Then
        assertThat(streamReference.get()).isNotNull();
    }

    @Test
    void blockingCreateUnirectionalStreamContinuesWhenMaxStreamsIsIncreased() throws Exception {
        // Given
        streamManager.setInitialMaxStreamsUni(1);
        QuicStream firstStream = streamManager.createStream(false);
        assertThat(firstStream).isNotNull();

        AtomicReference<QuicStream> streamReference = new AtomicReference<>();
        new Thread(() -> {
            // Creating the stream should block, because there are not credits at the moment
            QuicStream stream = streamManager.createStream(false);
            streamReference.set(stream);
        }).start();

        Thread.sleep(50);  // Give parallel thread a little time to start, so it blocks before this thread continues
        assertThat(streamReference.get()).isNull();  // This should more or less prove the thread is blocking

        // When
        streamManager.process(new MaxStreamsFrame(2, false), PnSpace.App, Instant.now());
        Thread.sleep(50);  // Give parallel thread a little time to finish
        // Then
        assertThat(streamReference.get()).isNotNull();
    }

    @Test
    void creatingEarlyDataStreamShouldNotBlockWhenMaxStreamsReached() throws Exception {
        // Given
        streamManager.setInitialMaxStreamsUni(1);
        QuicStream firstStream = streamManager.createStream(false);
        assertThat(firstStream).isNotNull();

        // When
        QuicStream earlyDataStream = streamManager.createEarlyDataStream(true);

        // Then
        assertThat(earlyDataStream).isNull();
    }

    @Test
    void serverInitiatedStreamShouldHaveOddId() {
        // Given
        streamManager = new StreamManager(mock(QuicConnectionImpl.class), Role.Server, mock(Logger.class));
        streamManager.setInitialMaxStreamsUni(1);

        // When
        QuicStream stream = streamManager.createStream(false);

        // Then
        assertThat(stream.getStreamId() % 4).isEqualTo(3);   // 0x3  | Server-Initiated, Unidirectional
        assertThat(stream.getStreamId() % 2).isEqualTo(1);
    }

    @Test
    void inServerRoleClientInitiatedStreamCausesCallback() {
        // Given
        streamManager = new StreamManager(mock(QuicConnectionImpl.class), Role.Server, mock(Logger.class));
        streamManager.setInitialMaxStreamsBidi(1);
        List<QuicStream> openedStreams = new ArrayList<>();
        streamManager.setPeerInitiatedStreamCallback(stream -> openedStreams.add(stream));

        // When
        streamManager.process(new StreamFrame(0, new byte[100], true));

        // Then
        assertThat(openedStreams).hasSize(1);
        assertThat(openedStreams.get(0).getStreamId()).isEqualTo(0);
    }
}
