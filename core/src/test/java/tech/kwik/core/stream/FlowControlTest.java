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
package tech.kwik.core.stream;

import tech.kwik.core.QuicStream;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.TransportParameters;
import tech.kwik.core.frame.MaxDataFrame;
import tech.kwik.core.frame.MaxStreamDataFrame;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class FlowControlTest {

    private QuicConnectionImpl conn;
    private ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    private StreamManager sm;
    private Role role;

    @BeforeEach
    void initMockConnection() {
        conn = mock(QuicConnectionImpl.class);
        sm = mock(StreamManager.class);
        role = Role.Client;
    }

    @Test
    void initialCreditsIsLimitedByInitialMaxData() {
        int initialMaxData = 1000;
        FlowControl fc = new FlowControl(Role.Client, initialMaxData, 9999, 9999, 9999);

        assertThat(fc.increaseFlowControlLimit(new QuicStreamImpl(1, role, conn, sm, fc), Long.MAX_VALUE)).isEqualTo(initialMaxData);
    }

    @Test
    void initialCreditsClientInitiatedBidirectionalIsLimited() {
        int initialMaxData = 1000;
        int initialServerMaxStreamData = 500;
        int streamId = 4;  // Client-initiated bidi: least significant two bits = 00

        // A client initiated stream is limited by the server's initial remote (initiated) limit
        FlowControl fc = new FlowControl(Role.Client, initialMaxData, 9999, initialServerMaxStreamData, 9999);

        assertThat(fc.increaseFlowControlLimit(new QuicStreamImpl(streamId, role, conn, sm, fc), Long.MAX_VALUE)).isEqualTo(500);
    }

    @Test
    void initialCreditsServerInitiatedBidirectionalIsLimited() {
        int initialMaxData = 1000;
        int initialServerMaxStreamData = 500;
        int streamId = 5;  // Server-initiated bidi: least significant two bits = 01

        // A server initiated stream is limited by the server's initial local (-ly initiated) limit
        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, 9999, 9999);

        assertThat(fc.increaseFlowControlLimit(new QuicStreamImpl(streamId, role, conn, sm, fc), Long.MAX_VALUE)).isEqualTo(500);
    }

    @Test
    void initialCreditsClientInitiatedUnidirectionalIsLimited() {
        int initialMaxData = 1000;
        int initialServerMaxStreamData = 500;
        int streamId = 6;  // Client-initiated uni: least significant two bits = 02

        // A client initiated stream is limited by the server's initial remote
        FlowControl fc = new FlowControl(Role.Client, initialMaxData, 9999, 9999, initialServerMaxStreamData);

        assertThat(fc.increaseFlowControlLimit(new QuicStreamImpl(streamId, role, conn, sm, fc), Long.MAX_VALUE)).isEqualTo(500);
    }

    @Test
    void streamsAreAllLimitedByTheSharedMaxData() {
        int initialMaxData = 900;
        int initialServerMaxStreamData = 500;
        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        int streamId1 = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream1 = new QuicStreamImpl(streamId1, role, conn, sm, fc);
        int streamId2 = 0;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream2 = new QuicStreamImpl(streamId2, role, conn, sm, fc);


        assertThat(fc.increaseFlowControlLimit(stream1, 500)).isEqualTo(500);
        assertThat(fc.increaseFlowControlLimit(stream2, 500)).isEqualTo(400);
        assertThat(fc.increaseFlowControlLimit(stream1, 600)).isEqualTo(500);
        assertThat(fc.increaseFlowControlLimit(stream2, 600)).isEqualTo(400);
    }

    @Test
    void maxDataIncreasesStreamLimit() {
        int initialMaxData = 100;
        int initialServerMaxStreamData = 500;
        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);

        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(100);

        fc.process(new MaxDataFrame(300));
        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(300);

        fc.process(new MaxDataFrame(400));
        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(400);
    }

    @Test
    void maxDataIncreaseIsSharedBetweenStreams() {
        int initialMaxData = 300;
        int initialServerMaxStreamData = 1000;
        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        int streamId1 = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream1 = new QuicStreamImpl(streamId1, role, conn, sm, fc);
        int streamId2 = 0;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream2 = new QuicStreamImpl(streamId2, role, conn, sm, fc);


        assertThat(fc.increaseFlowControlLimit(stream1, 200)).isEqualTo(200);
        assertThat(fc.increaseFlowControlLimit(stream2, 200)).isEqualTo(100);

        fc.process(new MaxDataFrame(600));
        assertThat(fc.increaseFlowControlLimit(stream1, 400)).isEqualTo(400);
        assertThat(fc.increaseFlowControlLimit(stream2, 400)).isEqualTo(200);
    }

    @Test
    void maxStreamDataIncreasesStreamLimit() throws Exception {
        int initialMaxData = 500;
        int initialServerMaxStreamData = 100;
        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);


        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(100);

        fc.process(new MaxStreamDataFrame(streamId, 300));
        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(300);
    }

    @Test
    void streamNotBlockedNotCalledWhenNotBlockedOnlyByMaxData() throws InterruptedException {
        int initialMaxData = 200;
        int initialServerMaxStreamData = 200;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test

        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        FlowControlUpdateListener listener = mock(FlowControlUpdateListener.class);
        fc.register(stream, listener);

        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(200);

        // When
        fc.process(new MaxDataFrame(400));

        // Then
        verify(listener, never()).streamNotBlocked(anyInt());

        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(200);
    }

    @Test
    void streamUnblocksWhenMaxDataIsIncreased() throws InterruptedException {
        int initialMaxData = 100;
        int initialServerMaxStreamData = 500;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test

        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        FlowControlUpdateListener listener = mock(FlowControlUpdateListener.class);
        fc.register(stream, listener);

        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(100);

        // When
        fc.process(new MaxDataFrame(200));

        // Then
        verify(listener).streamNotBlocked(anyInt());

        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(200);
    }

    @Test
    void streamUnblocksWhenMaxStreamDataIsIncreased() throws Exception {
        int initialMaxData = 500;
        int initialServerMaxStreamData = 100;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test

        // Given
        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        FlowControlUpdateListener listener = mock(FlowControlUpdateListener.class);
        fc.register(stream, listener);

        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(100);

        // When
        fc.process(new MaxStreamDataFrame(streamId, 300));

        // Then
        verify(listener, times(1)).streamNotBlocked(anyInt());
        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(300);
    }

    @Test
    void whenOutOfOrderMaxDataIsReceivedCurrentMaxDataIsNotReduced() {
        int initialMaxData = 500;
        int initialServerMaxStreamData = 2000;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test

        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(500);

        fc.process(new MaxDataFrame(1500));
        fc.process(new MaxDataFrame(1000));

        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(1500);
    }

    @Test
    void whenOutOfOrderMaxStreamDataIsReceivedCurrentMaxDataIsNotReduced() throws Exception {
        int initialMaxData = 5000;
        int initialServerMaxStreamData = 500;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test

        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(500);

        fc.process(new MaxStreamDataFrame(1, 1500));
        fc.process(new MaxStreamDataFrame(1, 1000));

        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(1500);
    }

    @Test
    void maxStreamDataFrameForClosedStreamIsIgnored() throws Exception {
        // Given
        FlowControl fc = new FlowControl(Role.Client, 100, 100, 100, 100);
        QuicStream stream = new QuicStreamImpl(1, role, conn, sm, fc);
        fc.streamOpened(stream);

        // When
        fc.streamClosed(stream);

        // Then
        // processing should not throw an exception
        fc.process(new MaxStreamDataFrame(1, 1500));
    }

    @Test
    void maxStreamDataFrameForNeverOpenedStreamMustLeadToStreamStateError() throws Exception {
        // Given
        FlowControl fc = new FlowControl(Role.Client, 100, 100, 100, 100);
        QuicStream stream = new QuicStreamImpl(0, role, conn, sm, fc);
        fc.streamOpened(stream);

        assertThatThrownBy(() ->
                // When
                fc.process(new MaxStreamDataFrame(4, 1500))   // Client role, so 4 is locally initiated
                // Then
        ).isInstanceOf(TransportError.class);
    }

    @Test
    void maxStreamDataFrameForNeverOpenedRemoteInitiaedStreamIsIgnored() throws Exception {
        // Given
        FlowControl fc = new FlowControl(Role.Client, 100, 100, 100, 100);

        // Then
        // processing should not throw an exception
        fc.process(new MaxStreamDataFrame(1, 1500));   // 1 = server initiated bidirectional
    }

    @Test
    void updateInitialMaxData() {
        int initialMaxData = 1000;
        int initialServerMaxStreamData = 1500;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test

        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(1000);

        TransportParameters updateTransportParameters = new TransportParameters();
        updateTransportParameters.setInitialMaxData(1400);   // This is the update
        updateTransportParameters.setInitialMaxStreamDataUni(initialServerMaxStreamData);
        updateTransportParameters.setInitialMaxStreamDataBidiLocal(initialServerMaxStreamData);
        updateTransportParameters.setInitialMaxStreamDataBidiRemote(initialServerMaxStreamData);
        fc.updateInitialValues(updateTransportParameters);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(1400);
    }

    @Test
    void whenInitialMaxDataIsUpdatedCurrentMaxDataIsNotReduced() {
        int initialMaxData = 500;
        int initialServerMaxStreamData = 2000;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test

        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(500);

        fc.process(new MaxDataFrame(1500));

        TransportParameters updateTransportParameters = new TransportParameters();
        updateTransportParameters.setInitialMaxData(1000);   // This is the update
        updateTransportParameters.setInitialMaxStreamDataUni(initialServerMaxStreamData);
        updateTransportParameters.setInitialMaxStreamDataBidiLocal(initialServerMaxStreamData);
        updateTransportParameters.setInitialMaxStreamDataBidiRemote(initialServerMaxStreamData);
        fc.updateInitialValues(updateTransportParameters);
        assertThat(fc.increaseFlowControlLimit(stream, 2000)).isEqualTo(1500);
    }

    @Test
    void updateInitialMaxStreamDataClientInitiatedBidirectionalStream() {
        int initialMaxData = 5000;
        int initialServerMaxStreamData = 500;
        int streamId = 0;  // Client initiated bi-di

        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(500);

        TransportParameters updateTransportParameters = new TransportParameters();
        updateTransportParameters.setInitialMaxData(initialMaxData);
        updateTransportParameters.setInitialMaxStreamDataUni(initialServerMaxStreamData);
        updateTransportParameters.setInitialMaxStreamDataBidiLocal(initialServerMaxStreamData);
        updateTransportParameters.setInitialMaxStreamDataBidiRemote(1000);   // This is the update
        fc.updateInitialValues(updateTransportParameters);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(1000);
    }

    @Test
    void updateInitialMaxStreamDataServerInitiatedBidirectionalStream() {
        int initialMaxData = 5000;
        int initialServerMaxStreamData = 500;
        int streamId = 1;  // Server initiated bi-di

        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(500);

        TransportParameters updateTransportParameters = new TransportParameters();
        updateTransportParameters.setInitialMaxData(initialMaxData);
        updateTransportParameters.setInitialMaxStreamDataUni(initialServerMaxStreamData);
        updateTransportParameters.setInitialMaxStreamDataBidiLocal(1000);   // This is the update
        updateTransportParameters.setInitialMaxStreamDataBidiRemote(initialServerMaxStreamData);
        fc.updateInitialValues(updateTransportParameters);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(1000);
    }

    @Test
    void updateInitialMaxStreamDataServerInitiatedBidirectionalStreamWithSmallerValueThanActual() throws Exception {
        int initialMaxData = 5000;
        int initialServerMaxStreamData = 500;
        int streamId = 1;  // Server initiated bi-di

        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(500);

        fc.process(new MaxStreamDataFrame(1, 1500));

        TransportParameters updateTransportParameters = new TransportParameters();
        updateTransportParameters.setInitialMaxData(initialMaxData);
        updateTransportParameters.setInitialMaxStreamDataUni(initialServerMaxStreamData);
        updateTransportParameters.setInitialMaxStreamDataBidiLocal(1000);   // This is the update
        updateTransportParameters.setInitialMaxStreamDataBidiRemote(initialServerMaxStreamData);
        fc.updateInitialValues(updateTransportParameters);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(1500);
    }

    @Test
    void updateInitialMaxStreamDataUnidirectionalStream() throws Exception {
        int initialMaxData = 5000;
        int initialServerMaxStreamData = 500;
        int streamId = 2;  // Client initiated uni

        FlowControl fc = new FlowControl(Role.Client, initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(500);

        TransportParameters updateTransportParameters = new TransportParameters();
        updateTransportParameters.setInitialMaxData(initialMaxData);
        updateTransportParameters.setInitialMaxStreamDataUni(1000);
        updateTransportParameters.setInitialMaxStreamDataBidiLocal(initialServerMaxStreamData);   // This is the update
        updateTransportParameters.setInitialMaxStreamDataBidiRemote(initialServerMaxStreamData);
        fc.updateInitialValues(updateTransportParameters);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(1000);
    }

    @Test
    void increasingServerFlowControlLimitForUnidirectionalClientInitiatedUsesInitialMaxStreamDataUni() {
        int initialMaxData = 5000;
        int initialClientMaxStreamData = 500;
        int streamId = 2;  // Client initiated uni

        // When used in server, a client initiated stream is initially limited by (the client's TP) initial_max_stream_data_uni
        FlowControl fc = new FlowControl(Role.Server, initialMaxData, 0, 0, initialClientMaxStreamData);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        long newLimit = fc.increaseFlowControlLimit(stream, 1000);

        assertThat(newLimit).isEqualTo(500);
    }

    @Test
    void increasingServerFlowControlLimitForBidirectionalClientInitiatedUsesInitialMaxStreamDataLocal() {
        int initialMaxData = 5000;
        int initialClientMaxStreamData = 500;
        int streamId = 0;  // Client initiated bidi.

        // When used in server, a client initiated stream is initially limited by (the client's TP) initial_max_stream_data_bidi_local
        FlowControl fc = new FlowControl(Role.Server, initialMaxData, initialClientMaxStreamData, 0, 0);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        long newLimit = fc.increaseFlowControlLimit(stream, 1000);

        assertThat(newLimit).isEqualTo(500);
    }

    @Test
    void increasingServerFlowControlLimitForBidirectionalServerInitiatedUsesInitialMaxStreamDataRemote() {
        int initialMaxData = 5000;
        int initialClientMaxStreamData = 500;
        int streamId = 1;  // Server initiated bidi

        // When used in server, a server initiated stream is initially limited by (the client's TP) initial_max_stream_data_bidi_remote
        FlowControl fc = new FlowControl(Role.Server, initialMaxData, 0, initialClientMaxStreamData, 0);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        long newLimit = fc.increaseFlowControlLimit(stream, 1000);

        assertThat(newLimit).isEqualTo(500);
    }

    @Test
    void whenLimitIncreasedStreamNotBlockedIsNotUnblocked() throws Exception {
        int streamId = 1;
        FlowControl fc = new FlowControl(Role.Client, 100000, 100, 100, 100);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        FlowControlUpdateListener listener = mock(FlowControlUpdateListener.class);
        fc.register(stream, listener);

        fc.increaseFlowControlLimit(stream, 99);  // So: not blocked (yet)

        fc.process(new MaxStreamDataFrame(1, 999));

        verify(listener, never()).streamNotBlocked(anyInt());
    }

    @Test
    void whenLimitIncreasedBlockedStreamIsUnblocked() throws Exception {
        int streamId = 1;
        FlowControl fc = new FlowControl(Role.Client, 100000, 100, 100, 100);
        QuicStream stream = new QuicStreamImpl(streamId, role, conn, sm, fc);
        FlowControlUpdateListener listener = mock(FlowControlUpdateListener.class);
        fc.register(stream, listener);

        fc.increaseFlowControlLimit(stream, 101);  // So: blocked

        fc.process(new MaxStreamDataFrame(1, 999));

        verify(listener, times(1)).streamNotBlocked(anyInt());
    }

    @Test
    void whenDataLimitIncreasedOnlyBlockedStreamsAreUnblocked() {
        FlowControl fc = new FlowControl(Role.Client, 100, 100, 100, 100);
        QuicStream stream1 = new QuicStreamImpl(1, role, conn, sm, fc);
        FlowControlUpdateListener listener1 = mock(FlowControlUpdateListener.class);
        fc.register(stream1, listener1);

        QuicStream stream2 = new QuicStreamImpl(5, role, conn, sm, fc);
        FlowControlUpdateListener listener2 = mock(FlowControlUpdateListener.class);
        fc.register(stream2, listener2);

        fc.increaseFlowControlLimit(stream1, 100);  // So: blocked (by both data and stream limit)
        fc.increaseFlowControlLimit(stream2, 50);

        fc.process(new MaxDataFrame(999));

        verify(listener1, never()).streamNotBlocked(anyInt());
        verify(listener2, times(1)).streamNotBlocked(anyInt());
    }

    @Test
    void initiallyStreamIsNotBlocked() {
        // Given
        FlowControl fc = new FlowControl(Role.Client, 100, 100, 100, 100);
        QuicStreamImpl stream = new QuicStreamImpl(1, role, conn, sm, fc);

        // When
        // (nothing)

        // Then
        BlockReason blockReason = fc.getFlowControlBlockReason(stream);
        assertThat(blockReason).isEqualTo(BlockReason.NOT_BLOCKED);
    }

    @Test
    void testBlockReasonWhenStreamLimitIsReached() {
        // Given
        FlowControl fc = new FlowControl(Role.Client, 1000, 100, 100, 100);
        QuicStreamImpl stream = new QuicStreamImpl(1, role, conn, sm, fc);

        // When
        fc.increaseFlowControlLimit(stream, 345);

        // Then
        BlockReason blockReason = fc.getFlowControlBlockReason(stream);
        assertThat(blockReason).isEqualTo(BlockReason.STREAM_DATA_BLOCKED);
    }

    @Test
    void testBlockReasonWhenConnectionLimitIsReached() {
        // Given
        FlowControl fc = new FlowControl(Role.Client, 100, 1000, 1000, 1000);
        QuicStreamImpl stream = new QuicStreamImpl(1, role, conn, sm, fc);

        // When
        fc.increaseFlowControlLimit(stream, 345);

        // Then
        BlockReason blockReason = fc.getFlowControlBlockReason(stream);
        assertThat(blockReason).isEqualTo(BlockReason.DATA_BLOCKED);
        assertThat(fc.getConnectionDataLimit()).isEqualTo(100);
    }
}
