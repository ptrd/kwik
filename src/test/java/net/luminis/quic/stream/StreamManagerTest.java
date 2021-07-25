/*
 * Copyright © 2020, 2021 Peter Doornbosch
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

import net.luminis.quic.*;
import net.luminis.quic.frame.MaxStreamsFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class StreamManagerTest {

    private StreamManager streamManager;
    private QuicConnectionImpl quicConnection;

    @BeforeEach
    void init() {
        quicConnection = mock(QuicConnectionImpl.class);
        streamManager = new StreamManager(quicConnection, Role.Client, mock(Logger.class), 10, 10);
        streamManager.setFlowController(mock(FlowControl.class));
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
        streamManager.process(new MaxStreamsFrame(8, true));
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
        streamManager.process(new MaxStreamsFrame(8, false));
        QuicStream stream2 = streamManager.createStream(false);

        // Then
        assertThat(stream1).isNotNull();
        assertThat(stream2).isNotNull();
    }

    @Test
    void maxBidiStreamsCanNeverDecrease() {
        // Given
        streamManager.setInitialMaxStreamsBidi(1);
        streamManager.process(new MaxStreamsFrame(8, true));

        // When
        streamManager.process(new MaxStreamsFrame(5, true));

        // Then
        assertThat(streamManager.getMaxBidirectionalStreams()).isGreaterThanOrEqualTo(8);
    }

    @Test
    void maxUniStreamsCanNeverDecrease() {
        // Given
        streamManager.setInitialMaxStreamsUni(1);
        streamManager.process(new MaxStreamsFrame(8, false));

        // When
        streamManager.process(new MaxStreamsFrame(5, false));

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
        streamManager.process(new MaxStreamsFrame(2, true));
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
        streamManager.process(new MaxStreamsFrame(2, false));
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
        QuicStreamImpl earlyDataStream = streamManager.createEarlyDataStream(true);

        // Then
        assertThat(earlyDataStream).isNull();
    }

    @Test
    void serverInitiatedStreamShouldHaveOddId() {
        // Given
        streamManager = new StreamManager(mock(QuicConnectionImpl.class), Role.Server, mock(Logger.class), 10, 10);
        streamManager.setFlowController(mock(FlowControl.class));
        streamManager.setInitialMaxStreamsUni(1);

        // When
        QuicStream stream = streamManager.createStream(false);

        // Then
        assertThat(stream.getStreamId() % 4).isEqualTo(3);   // 0x3  | Server-Initiated, Unidirectional
        assertThat(stream.getStreamId() % 2).isEqualTo(1);
    }

    @Test
    void inServerRoleClientInitiatedStreamCausesCallback() throws Exception {
        // Given
        streamManager = new StreamManager(mock(QuicConnectionImpl.class), Role.Server, mock(Logger.class), 10, 10);
        streamManager.setFlowController(mock(FlowControl.class));
        streamManager.setInitialMaxStreamsBidi(1);
        List<QuicStream> openedStreams = new ArrayList<>();
        streamManager.setPeerInitiatedStreamCallback(stream -> openedStreams.add(stream));

        // When
        streamManager.process(new StreamFrame(0, new byte[100], true));

        // Then
        assertThat(openedStreams).hasSize(1);
        assertThat(openedStreams.get(0).getStreamId()).isEqualTo(0);
    }

    @Test
    void whenStreamLimitIsReachedCreateStreamLeadsToTransportErrorException() throws Exception {
        // Given
        int i;
        for (i = 0; i < 10; i++) {
            streamManager.process(new StreamFrame(i * 4 + 1, new byte[0], false));
        }

        int next = i;
        assertThatThrownBy(() ->
                // When
                streamManager.process(new StreamFrame(next * 4 + 1, new byte[0], false)))
                // Then
                .isInstanceOf(TransportError.class);
    }

    @Test
    void whenStreamLimitIsReachedImplicitlyCreateStreamLeadsToTransportErrorException() throws Exception {
        // Given
        streamManager.process(new StreamFrame(9 * 4 + 1, new byte[0], false));

        int next = 10;
        assertThatThrownBy(() ->
                // When
                streamManager.process(new StreamFrame(next * 4 + 1, new byte[0], false)))
                // Then
                .isInstanceOf(TransportError.class);
    }

    @Test
    void whenStreamIsClosedOneMoreCanBeOpened() throws Exception {
        // Given
        int streamId = 9 * 4 + 1;
        streamManager.process(new StreamFrame(streamId, new byte[0], false));

        // When
        StreamFrame closeFrame = new StreamFrame(streamId, new byte[0], true);
        streamManager.process(closeFrame);

        // Then
        int nextStreamId = 10 * 4 + 1;
        // Assert that the next line does not throw
        streamManager.process(new StreamFrame(nextStreamId, new byte[0], false));
        // And
        verifyMaxStreamsFrameIsToBeSent(11);
    }

    @Test
    void whenStreamIsClosedInSameFrameOneMoreCanBeOpened() throws Exception {
        // Given
        int streamId = 9 * 4 + 1;

        // When
        streamManager.process(new StreamFrame(streamId, new byte[0], true));

        // Then
        int nextStreamId = 10 * 4 + 1;
        // Assert that the next line does not throw
        streamManager.process(new StreamFrame(nextStreamId, new byte[0], false));
        // And
        verifyMaxStreamsFrameIsToBeSent(11);
    }

    @Test
    void whenMultipleStreamsAreClosedOnlyOneMaxStreamsFrameIsSent() throws Exception {
        // When
        for (int i = 0; i < 10; i++) {
            streamManager.process(new StreamFrame(i * 4 + 1, new byte[0], true));
        }

        verifyMaxStreamsFrameIsToBeSent(20);
    }

    void verifyMaxStreamsFrameIsToBeSent(int expectedMaxStreams) {
        ArgumentCaptor<Function<Integer, QuicFrame>> captor = ArgumentCaptor.forClass(Function.class);
        verify(quicConnection).send(captor.capture(), anyInt(), any(EncryptionLevel.class), any(Consumer.class));
        QuicFrame frame = captor.getValue().apply(9);
        assertThat(frame).isInstanceOf(MaxStreamsFrame.class);
        assertThat(((MaxStreamsFrame) frame).getMaxStreams()).isEqualTo(expectedMaxStreams);
    }
}
