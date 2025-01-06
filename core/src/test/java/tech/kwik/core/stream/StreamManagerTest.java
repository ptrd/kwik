/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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

import tech.kwik.core.ConnectionConfig;
import tech.kwik.core.QuicStream;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.frame.MaxDataFrame;
import tech.kwik.core.frame.MaxStreamsFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.frame.ResetStreamFrame;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.log.Logger;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.test.FieldReader;
import tech.kwik.core.test.TestClock;
import tech.kwik.core.test.TestScheduledExecutor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;

import static tech.kwik.core.QuicConstants.TransportErrorCode.FINAL_SIZE_ERROR;
import static tech.kwik.core.QuicConstants.TransportErrorCode.FLOW_CONTROL_ERROR;
import static tech.kwik.core.QuicConstants.TransportErrorCode.STREAM_LIMIT_ERROR;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.*;

class StreamManagerTest {

    private StreamManager streamManager;
    private QuicConnectionImpl quicConnection;
    private ConnectionConfig defaultConfig;
    private TestScheduledExecutor callbackExecutor;

    //region setup
    @BeforeEach
    void init() {
        quicConnection = mock(QuicConnectionImpl.class);
        defaultConfig = ServerConnectionConfig.builder()
                .maxOpenPeerInitiatedUnidirectionalStreams(10)
                .maxOpenPeerInitiatedBidirectionalStreams(10)
                .maxConnectionBufferSize(10_000)
                .maxUnidirectionalStreamBufferSize(10_000)
                .maxBidirectionalStreamBufferSize(10_000)
                .build();
        callbackExecutor = new TestScheduledExecutor(new TestClock());
        streamManager = new StreamManager(quicConnection, Role.Client, mock(Logger.class), defaultConfig, callbackExecutor);
        streamManager.setFlowController(mock(FlowControl.class));
    }
    //endregion

    //region stream creation
    @Test
    void serverInitiatedStreamShouldHaveOddId() {
        // Given
        streamManager = new StreamManager(mock(QuicConnectionImpl.class), Role.Server, mock(Logger.class), defaultConfig, callbackExecutor);
        streamManager.setFlowController(mock(FlowControl.class));
        streamManager.setInitialMaxStreamsUni(1);

        // When
        QuicStream stream = streamManager.createStream(false);

        // Then
        assertThat(stream.getStreamId() % 4).isEqualTo(3);   // 0x3  | Server-Initiated, Unidirectional
        assertThat(stream.getStreamId() % 2).isEqualTo(1);
    }

    @Test
    void unidirectionalAndBidirectionalHaveSeparateIdSpaces() {
        // Given
        streamManager.setInitialMaxStreamsUni(10);
        streamManager.setInitialMaxStreamsBidi(10);
        streamManager.createStream(false);
        streamManager.createStream(false);
        QuicStream unidirectionalStream = streamManager.createStream(false);

        // When
        QuicStream bidirectional = streamManager.createStream(true);

        // Then
        assertThat(bidirectional.getStreamId()).isEqualTo(0x0);   // 0x0  | Client-Initiated, Bidirectional
        assertThat(unidirectionalStream.getStreamId()).isEqualTo(10);
    }

    @Test
    void bidirectionalAndUnidirectionalHaveSeparateIdSpaces() {
        // Given
        streamManager.setInitialMaxStreamsUni(10);
        streamManager.setInitialMaxStreamsBidi(10);
        streamManager.createStream(true);
        QuicStream bidirectional = streamManager.createStream(true);

        // When
        QuicStream unidirectionalStream = streamManager.createStream(false);

        // Then
        assertThat(unidirectionalStream.getStreamId()).isEqualTo(0x02);  // 0x2  | Client-Initiated, Unidirectional
        assertThat(bidirectional.getStreamId()).isEqualTo(4);
    }

    @Test
    void inServerRoleClientInitiatedStreamCausesCallback() throws Exception {
        // Given
        ServerConnectionConfig config = ServerConnectionConfig.builder()
                .maxOpenPeerInitiatedUnidirectionalStreams(10)
                .maxOpenPeerInitiatedBidirectionalStreams(10)
                .maxConnectionBufferSize(10_000)
                .maxBidirectionalStreamBufferSize(10_000)
                .build();
        streamManager = new StreamManager(quicConnection, Role.Server, mock(Logger.class), config, callbackExecutor);
        streamManager.setFlowController(mock(FlowControl.class));
        streamManager.setInitialMaxStreamsBidi(1);
        List<QuicStream> openedStreams = new ArrayList<>();
        streamManager.setPeerInitiatedStreamCallback(stream -> openedStreams.add(stream));

        // When
        streamManager.process(new StreamFrame(0, new byte[100], true));
        callbackExecutor.clockAdvanced();

        // Then
        assertThat(openedStreams).hasSize(1);
        assertThat(openedStreams.get(0).getStreamId()).isEqualTo(0);
    }

    @Test
    void numberOfBidirectionalStreamsThatCanBeCreatedShouldBeIdenticalToInitialMaxValue() throws Exception {
        // Given
        streamManager = new StreamManager(quicConnection, Role.Server, mock(Logger.class), defaultConfig, callbackExecutor);
        streamManager.setFlowController(mock(FlowControl.class));
        // streamManager.setInitialMaxStreamsBidi(10);

        // When
        List<Integer> openStreams = new ArrayList<>();
        int currentStreamId = 0x00;  // Client initiated, bidirectional
        try {
            while (true) {
                streamManager.process(new StreamFrame(currentStreamId, new byte[100], true));
                openStreams.add(currentStreamId);
                currentStreamId += 4;
            }
        }
        catch (TransportError e) {}

        // Then
        assertThat(openStreams).hasSize(10);
        assertThat(openStreams).containsExactly(0, 4, 8, 12, 16, 20, 24, 28, 32, 36);
    }
    //endregion

    //region self creation in relation to streams limit
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
    //endregion

    //region self creation with dynamically changing limits
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
    //endregion

    //region peer creation in relation to streams limit
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
                .isInstanceOf(TransportError.class)
                .extracting("errorCode").isEqualTo(STREAM_LIMIT_ERROR);
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
                .isInstanceOf(TransportError.class)
                .extracting("errorCode").isEqualTo(STREAM_LIMIT_ERROR);
    }

    @Test
    void whenStreamLimitIsReachedForServerInitiatedUnidirectionalCreateStreamShouldLeadToTransportErrorException() throws Exception {
        // Given
        int initial_stream_id_for_type = 3; // server initiated unidirectional stream
        int acceptedStreamId = 9 * 4 + initial_stream_id_for_type;
        streamManager.process(new StreamFrame(acceptedStreamId, new byte[0], false));

        int offendingStreamId = 10 * 4 + initial_stream_id_for_type;
        assertThatThrownBy(() ->
                // When
                streamManager.process(new StreamFrame(offendingStreamId, new byte[0], false)))
                // Then
                .isInstanceOf(TransportError.class)
                .extracting("errorCode").isEqualTo(STREAM_LIMIT_ERROR);
    }

    @Test
    void whenStreamLimitIsReachedForClientInitiatedUnidirectionalCreateStreamShouldLeadToTransportErrorException() throws Exception {
        // Given
        streamManager = new StreamManager(quicConnection, Role.Server, mock(Logger.class), defaultConfig, callbackExecutor);
        int initial_stream_id_for_type = 2; // client initiated unidirectional stream
        int acceptedStreamId = 9 * 4 + initial_stream_id_for_type;
        streamManager.process(new StreamFrame(acceptedStreamId, new byte[0], false));

        int offendingStreamId = 10 * 4 + initial_stream_id_for_type;
        assertThatThrownBy(() ->
                // When
                streamManager.process(new StreamFrame(offendingStreamId, new byte[0], false)))
                // Then
                .isInstanceOf(TransportError.class)
                .extracting("errorCode").isEqualTo(STREAM_LIMIT_ERROR);
    }

    @Test
    void whenStreamIsClosedOneMoreCanBeOpened() throws Exception {
        // Given
        int streamId = 9 * 4 + 1;
        streamManager.process(new StreamFrame(streamId, new byte[0], false));

        // When
        streamManager.streamClosed(streamId);

        // Then
        int nextStreamId = 10 * 4 + 1;
        // Assert that the next line does not throw
        streamManager.process(new StreamFrame(nextStreamId, new byte[0], false));
        // And
        verifyMaxStreamsFrameIsToBeSent(11);
    }

    @Test
    void whenMultipleStreamsAreClosedOnlyOneMaxStreamsFrameIsSent() throws Exception {
        // Given
        for (int i = 0; i < 10; i++) {
            streamManager.process(new StreamFrame(i * 4 + 1, new byte[0], true));
        }

        // When
        for (int i = 0; i < 10; i++) {
            streamManager.streamClosed(i * 4 + 1);
        }

        // Then
        verifyMaxStreamsFrameIsToBeSent(20);
    }

    @Test
    void whenSelfInitiatedUnidirectionalStreamIsClosedItShouldNotBePossibleToOpenMorePeerInitiated() throws Exception {
        // Given
        int streamId = 9 * 4 + 2;  // client initiated unidirectional stream
        streamManager.process(new StreamFrame(streamId, new byte[0], false));

        // When
        streamManager.streamClosed(streamId);

        // Then   (not a next server initiated stream can be opened)
        int nextStreamId = 10 * 4 + 3;
        assertThatThrownBy(() ->
                        streamManager.process(new StreamFrame(nextStreamId, new byte[0], false))
                // Then
        ).isInstanceOf(TransportError.class);
        // And
        verify(quicConnection, never()).send(any(Function.class), anyInt(), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void whenSelfInitiatedBidirectionalStreamIsClosedItShouldNotBePossibleToOpenMorePeerInitiated() throws Exception {
        // Given
        int streamId = 9 * 4 + 0;  // client initiated bidirectional stream
        streamManager.process(new StreamFrame(streamId, new byte[0], false));

        // When
        streamManager.streamClosed(streamId);

        // Then   (not a next server initiated stream can be opened)
        int nextStreamId = 10 * 4 + 1;
        assertThatThrownBy(() ->
                        streamManager.process(new StreamFrame(nextStreamId, new byte[0], false))
                // Then
        ).isInstanceOf(TransportError.class);
        // And
        verify(quicConnection, never()).send(any(Function.class), anyInt(), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void whenAbsoluteMaxUnidirectionalStreamsIsReachedNoMaxStreamsFrameIsSent() throws Exception {
        // Given
        ServerConnectionConfig config = ServerConnectionConfig.builder()
                .maxOpenPeerInitiatedUnidirectionalStreams(3)
                .maxTotalPeerInitiatedUnidirectionalStreams(3)
                .maxUnidirectionalStreamBufferSize(1_000)
                .maxConnectionBufferSize(1_000)
                .build();
        streamManager.initialize(config);
        int streamId = 0x03;  // server initiated unidirectional stream

        // When
        streamManager.process(new StreamFrame(streamId, new byte[0], false));
        streamManager.process(new StreamFrame(streamId + 4, new byte[0], false));
        streamManager.process(new StreamFrame(streamId + 8, new byte[0], false));
        streamManager.streamClosed(streamId);
        streamManager.streamClosed(streamId + 4);
        streamManager.streamClosed(streamId + 8);

        // Then
        verify(quicConnection, never()).send(any(Function.class), anyInt(), any(EncryptionLevel.class), any(Consumer.class));
        // And
        assertThatThrownBy(() ->
                        streamManager.process(new StreamFrame(streamId + 12, new byte[0], false))
        ).isInstanceOf(TransportError.class);
    }

    @Test
    void whenAbsoluteMaxBidirectionalStreamsIsReachedNoMaxStreamsFrameIsSent() throws Exception {
        // Given
        ServerConnectionConfig config = ServerConnectionConfig.builder()
                .maxOpenPeerInitiatedBidirectionalStreams(3)
                .maxTotalPeerInitiatedBidirectionalStreams(3)
                .maxBidirectionalStreamBufferSize(1_000)
                .maxConnectionBufferSize(1_000)
                .build();
        streamManager.initialize(config);
        int streamId = 0x01;  // server initiated bidirectional stream

        // When
        streamManager.process(new StreamFrame(streamId, new byte[0], false));
        streamManager.process(new StreamFrame(streamId + 4, new byte[0], false));
        streamManager.process(new StreamFrame(streamId + 8, new byte[0], false));
        streamManager.streamClosed(streamId);
        streamManager.streamClosed(streamId + 4);
        streamManager.streamClosed(streamId + 8);

        // Then
        verify(quicConnection, never()).send(any(Function.class), anyInt(), any(EncryptionLevel.class), any(Consumer.class));
        // And
        assertThatThrownBy(() ->
                streamManager.process(new StreamFrame(streamId + 12, new byte[0], false))
        ).isInstanceOf(TransportError.class);
    }
    //endregion

    //region max streams
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
        assertThat(streamManager.getMaxUnidirectionalStreams()).isGreaterThanOrEqualTo(8);
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

        assertThat(streamManager.getMaxUnidirectionalStreams()).isEqualTo(10);
    }
    //endregion
    
    //region flow control
    @Test
    void updatingConnectionFlowControlShouldSendMaxData() throws Exception {
        long flowControlIncrement = (long) new FieldReader(streamManager, streamManager.getClass().getDeclaredField("flowControlIncrement")).read();

        streamManager.updateConnectionFlowControl(10);
        verify(quicConnection, never()).send(any(QuicFrame.class), any(Consumer.class), anyBoolean());  // No initial update, value is advertised in transport parameters.

        streamManager.updateConnectionFlowControl((int) flowControlIncrement);
        verify(quicConnection).send(argThat(f -> f instanceof MaxDataFrame), any(Consumer.class), anyBoolean());

        clearInvocations(quicConnection);
        streamManager.updateConnectionFlowControl((int) (flowControlIncrement * 0.8));
        verify(quicConnection, never()).send(argThat(f -> f instanceof MaxDataFrame), any(Consumer.class), anyBoolean());

        clearInvocations(quicConnection);
        streamManager.updateConnectionFlowControl((int) (flowControlIncrement * 0.21));
        verify(quicConnection).send(argThat(f -> f instanceof MaxDataFrame), any(Consumer.class), anyBoolean());
    }

    @Test
    void incomingStreamDataShouldBeAcceptedWhenConnectionLimitNotReached() throws Exception {
        // When
        assertThatCode(() ->
                // When
                streamManager.process(new StreamFrame(0, 9_999, new byte[1], false)))
                // Then
                .doesNotThrowAnyException();
    }

    @Test
    void shouldThrowTransportErrorWhenConnectionFlowControlLimitIsExceeded() throws Exception {
        // When
        assertThatThrownBy(() ->
                // When
                streamManager.process(new StreamFrame(1, 9_999, new byte[2], false)))
                // Then
                .isInstanceOf(TransportError.class)
                .extracting("errorCode").isEqualTo(FLOW_CONTROL_ERROR);
    }

    @Test
    void shouldThrowTransportErrorWhenConnectionFlowControlLimitIsExceeded2() throws Exception {
        // Given
        streamManager.process(new StreamFrame(1, 3_000, new byte[300], false));
        streamManager.process(new StreamFrame(5, 3_000, new byte[300], false));
        streamManager.process(new StreamFrame(9, 3_000, new byte[300], false));

        // When
        assertThatThrownBy(() ->
                // When
                streamManager.process(new StreamFrame(5, 3_000 + 300, new byte[101], false)))
                // Then
                .isInstanceOf(TransportError.class)
                .extracting("errorCode").isEqualTo(FLOW_CONTROL_ERROR);
    }

    @Test
    void connectionFlowControlLimitIncreasesWhenDataIsRead() throws Exception {
        // Given
        streamManager.setInitialMaxStreamsBidi(1);
        QuicStream stream = streamManager.createStream(true);
        streamManager.process(new StreamFrame(stream.getStreamId(), new byte[10_000], false));

        // When
        stream.getInputStream().read(new byte[10_000]);

        // Then
        verify(quicConnection)
                .send(argThat(f -> f instanceof MaxDataFrame && ((MaxDataFrame) f).getMaxData() == 20_000),
                        any(Consumer.class), anyBoolean());
    }

    @Test
    void connectionFlowControlCreditsOfClosedStreamsShouldCount() throws Exception {
        // Given
        Map<Integer, QuicStream> openStreams = new HashMap<>();
        streamManager.setPeerInitiatedStreamCallback(stream -> {
            openStreams.put(stream.getStreamId(), stream);
        });
        streamManager.process(new StreamFrame(3, new byte[5000], false));
        streamManager.process(new StreamFrame(7, new byte[5000], false));
        callbackExecutor.clockAdvanced();
        for (QuicStream stream : openStreams.values()) {
            stream.getInputStream().read(new byte[5000]);  // Will increase connection flow control limit to 20.000
        }

        // When
        for (QuicStream stream : openStreams.values()) {
            stream.getInputStream().close();  // Should have no affect on connection flow control limit!
        }

        // Then
        assertThatCode(() ->
                // When
                streamManager.process(new StreamFrame(11, new byte[10000], false)))
                // Then
                .doesNotThrowAnyException();
        assertThatThrownBy(() ->
                // When
                streamManager.process(new StreamFrame(15, new byte[1], false)))
                // Then
                .isInstanceOf(TransportError.class)
                .extracting("errorCode").isEqualTo(FLOW_CONTROL_ERROR);
    }

    @Test
    void whenResetReceivedUnusedCreditsShouldBeReturnedToConnectionFlowControl() throws Exception {
        // Given
        int streamId = 3;
        streamManager.setInitialMaxStreamsBidi(1);
        streamManager.process(new StreamFrame(streamId, new byte[1_000], false));

        // When
        streamManager.process(new ResetStreamFrame(streamId, 0, 7_000));

        // Then
        verify(quicConnection)
                .send(argThat(f -> f instanceof MaxDataFrame && ((MaxDataFrame) f).getMaxData() == 17_000),
                        any(Consumer.class), anyBoolean());
    }

    @Test
    void finalSizeOfResetFrameShouldBeUsedForConnectionFlowControl() throws Exception {
        // Given
        int streamId = 1;
        streamManager.setInitialMaxStreamsBidi(1);
        streamManager.process(new StreamFrame(streamId, new byte[1_000], false));  // Leaves 9.000 credits for connection flow control

        // When
        streamManager.process(new ResetStreamFrame(streamId, 0, 3_000));  // Leaves 7.000 credits for connection flow control
        // However, new credits with the amount of the final size well be added to the connection flow control limit => 10.000 credits

        // Then
        int nextStreamId = 5;
        assertThatCode(() ->
                // When
                streamManager.process(new StreamFrame(nextStreamId, new byte[10000], false)))
                // Then
                .doesNotThrowAnyException();

        assertThatThrownBy(() ->
                // When
                streamManager.process(new StreamFrame(nextStreamId, 10000, new byte[1], false)))
                // Then
                .isInstanceOf(TransportError.class)
                .extracting("errorCode").isEqualTo(FLOW_CONTROL_ERROR);
    }

    @Test
    void recevingRetransmittedStreamFrameOnClosedOnSelfInitiatedStreamShouldNotLeadToFlowControlError() throws Exception {
        // Given
        streamManager.setInitialMaxStreamsBidi(2);
        streamManager.setInitialMaxStreamsUni(2);
        QuicStream dummyStream = streamManager.createStream(true);  // Create a stream to make sure the stream id is not 0
        QuicStream stream = streamManager.createStream(true);
        stream.resetStream(9);  // Close output so reading all input will close stream.

        long streamOffset = 0;
        for (int i = 0; i < 16; i++) {  // Read a lot of data to make sure connection flow control limit is increased
            streamManager.process(new StreamFrame(stream.getStreamId(), streamOffset, new byte[1024], false));
            streamOffset += 1024;
            stream.getInputStream().read(new byte[1024]);
        }

        streamManager.process(new StreamFrame(stream.getStreamId(), streamOffset, new byte[0], true));  // Final frame
        stream.getInputStream().read(new byte[1024]);  // Close stream, will cause stream to be removed from stream manager

        // When
        // Retransmitted stream frame is received with a high offset (close to the flow control limit)
        long streamFinalSize = streamOffset;
        assertThatCode(() ->
                streamManager.process(new StreamFrame(stream.getStreamId(), streamFinalSize - 5 * 1024, new byte[1024], false))
        ).doesNotThrowAnyException();
    }
    //endregion

    //region final size
    @Test
    void receivingStreamFrameThatGoesBeyondFinalSizeShouldThrow() throws Exception {
        // Given
        streamManager.process(new StreamFrame(1, new byte[300], true));

        // When
        assertThatThrownBy(() ->
                // When
                streamManager.process(new StreamFrame(1, 300, new byte[3], false)))
                // Then
                .isInstanceOf(TransportError.class)
                .extracting("errorCode").isEqualTo(FINAL_SIZE_ERROR);
    }

    @Test
    void receivingStreamFrameThatRedefinesFinalSizeShouldThrow() throws Exception {
        // Given
        streamManager.process(new StreamFrame(1, new byte[300], true));

        // When
        assertThatThrownBy(() ->
                // When
                streamManager.process(new StreamFrame(1, 200, new byte[3], true)))
                // Then
                .isInstanceOf(TransportError.class)
                .extracting("errorCode").isEqualTo(FINAL_SIZE_ERROR);
    }

    @Test
    void receivingAnotherFinalStreamFrameWithSameFinalSizeShouldNotThrow() throws Exception {
        // Given
        streamManager.process(new StreamFrame(1, new byte[300], true));

        // When
        assertThatCode(() ->
                // When
                streamManager.process(new StreamFrame(1, 200, new byte[100], true)))
                // Then
                .doesNotThrowAnyException();
    }

    @Test
    void receivingResetFrameThatRedefinesFinalSizeShouldThrow() throws Exception {
        // Given
        streamManager.process(new StreamFrame(1, new byte[300], true));

        // When
        assertThatThrownBy(() ->
                // When
                streamManager.process(new ResetStreamFrame(1, 9, 200)))
                // Then
                .isInstanceOf(TransportError.class)
                .extracting("errorCode").isEqualTo(FINAL_SIZE_ERROR);
    }
    //endregion

    //region closing streams
    @Test
    void closingSelfInitiatedStreamShouldRemoveItFromStreamManager() throws Exception {
        // Given
        streamManager.setInitialMaxStreamsBidi(1);
        QuicStream stream = streamManager.createStream(true);

        // When
        streamManager.streamClosed(stream.getStreamId());

        // Then
        assertThat(streamManager.openStreamCount()).isEqualTo(0);
    }

    @Test
    void closingSelfInitiatedStreamTwiceStillRemovesItOnceFromStreamManager() throws Exception {
        // Given
        streamManager.setInitialMaxStreamsBidi(1);
        QuicStream stream = streamManager.createStream(true);
        streamManager.streamClosed(stream.getStreamId());

        // When
        streamManager.streamClosed(stream.getStreamId());

        // Then
        assertThat(streamManager.openStreamCount()).isEqualTo(0);
    }

    @Test
    void closingPeerInitiatedStreamShouldRemoveItFromStreamManager() throws Exception {
        // Given
        int streamId = 1;
        streamManager.process(new StreamFrame(streamId, new byte[0], false));

        // When
        streamManager.streamClosed(streamId);

        // Then
        assertThat(streamManager.openStreamCount()).isEqualTo(0);
    }

    @Test
    void closedPeerInitiatedStreamWillNotBeReopened() throws Exception {
        // Given
        int streamId = 1;
        streamManager.process(new StreamFrame(streamId, new byte[0], false));
        streamManager.streamClosed(streamId);

        // When
        streamManager.process(new StreamFrame(streamId, new byte[0], false));

        // Then
        assertThat(streamManager.openStreamCount()).isEqualTo(0);
    }

    @Test
    void receivingDuplicateFinalStreamFrameAfterCloseBidiShouldNotLeadToException() throws Exception {
        // Given
        streamManager.setInitialMaxStreamsBidi(1);

        QuicStream stream = streamManager.createStream(true);
        int streamId = stream.getStreamId();

        streamManager.process(new StreamFrame(streamId, new byte[10_000], false));
        stream.getInputStream().read(new byte[10_000]);

        StreamFrame finalFrame = new StreamFrame(streamId, 10_000, new byte[10_000], true);
        streamManager.process(finalFrame);
        streamManager.streamClosed(streamId);

        // When
        assertThatCode(() ->
                // When
                streamManager.process(finalFrame))
                // Then
                .doesNotThrowAnyException();
    }

    @Test
    void receivingDuplicateFinalStreamFrameAfterCloseUniShouldNotLeadToException() throws Exception {
        // Given
        Map<Integer, QuicStream> openStreams = new HashMap<>();
        streamManager.setPeerInitiatedStreamCallback(stream -> {
            openStreams.put(stream.getStreamId(), stream);
        });

        int streamId = 0x03;
        streamManager.process(new StreamFrame(streamId, new byte[10_000], false));
        callbackExecutor.clockAdvanced();
        QuicStream stream = openStreams.get(streamId);
        stream.getInputStream().read(new byte[10_000]);

        StreamFrame finalFrame = new StreamFrame(streamId, 10_000, new byte[10_000], true);
        streamManager.process(finalFrame);
        streamManager.streamClosed(streamId);

        // When
        assertThatCode(() ->
                // When
                streamManager.process(finalFrame))
                // Then
                .doesNotThrowAnyException();
    }
    //endregion

    //region buffer size
    @Test
    void whenDefaultUnidirectionalStreamBufferSizeIsChangedNewStreamShouldUseNewValue() {
        // When
        streamManager.setDefaultUnidirectionalStreamReceiveBufferSize(6789);

        // Then
        assertThat(streamManager.getMaxUnidirectionalStreamBufferSize()).isEqualTo(6789);
        assertThat(streamManager.getMaxBidirectionalStreamBufferSize()).isEqualTo(10000);
    }

    @Test
    void whenDefaultBidirectionalStreamBufferSizeIsChangedNewStreamShouldUseNewValue() {
        // When
        streamManager.setDefaultBidirectionalStreamReceiveBufferSize(6789);

        // Then
        assertThat(streamManager.getMaxBidirectionalStreamBufferSize()).isEqualTo(6789);
        assertThat(streamManager.getMaxUnidirectionalStreamBufferSize()).isEqualTo(10000);
    }
    //endregion

    //region test helper methods
    void verifyMaxStreamsFrameIsToBeSent(int expectedMaxStreams) {
        ArgumentCaptor<Function<Integer, QuicFrame>> captor = ArgumentCaptor.forClass(Function.class);
        verify(quicConnection).send(captor.capture(), anyInt(), any(EncryptionLevel.class), any(Consumer.class));
        QuicFrame frame = captor.getValue().apply(9);
        assertThat(frame).isInstanceOf(MaxStreamsFrame.class);
        assertThat(((MaxStreamsFrame) frame).getMaxStreams()).isEqualTo(expectedMaxStreams);
    }
    //endregion
}
