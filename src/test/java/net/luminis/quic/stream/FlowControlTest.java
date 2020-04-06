/*
 * Copyright © 2019, 2020 Peter Doornbosch
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
import net.luminis.quic.TransportParameters;
import net.luminis.quic.frame.MaxDataFrame;
import net.luminis.quic.frame.MaxStreamDataFrame;
import net.luminis.quic.frame.MaxStreamsFrame;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class FlowControlTest {

    private QuicConnectionImpl conn;
    private ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    @BeforeEach
    void initMockConnection() {
        conn = Mockito.mock(QuicConnectionImpl.class);
    }

    @Test
    void initialCreditsIsLimitedByInitialMaxData() {
        int initialMaxData = 1000;
        FlowControl fc = new FlowControl(initialMaxData, 9999, 9999, 9999);

        assertThat(fc.increaseFlowControlLimit(new QuicStream(1, conn, null), Long.MAX_VALUE)).isEqualTo(initialMaxData);
    }

    @Test
    void initialCreditsClientInitiatedBidirectionalIsLimited() {
        int initialMaxData = 1000;
        int initialServerMaxStreamData = 500;
        int streamId = 4;  // Client-initiated bidi: least significant two bits = 00

        // A client initiated stream is limited by the server's initial remote (initiated) limit
        FlowControl fc = new FlowControl(initialMaxData, 9999, initialServerMaxStreamData, 9999);

        assertThat(fc.increaseFlowControlLimit(new QuicStream(streamId, conn, null), Long.MAX_VALUE)).isEqualTo(500);
    }

    @Test
    void initialCreditsServerInitiatedBidirectionalIsLimited() {
        int initialMaxData = 1000;
        int initialServerMaxStreamData = 500;
        int streamId = 5;  // Server-initiated bidi: least significant two bits = 01

        // A server initiated stream is limited by the server's initial local (-ly initiated) limit
        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, 9999, 9999);

        assertThat(fc.increaseFlowControlLimit(new QuicStream(streamId, conn, null), Long.MAX_VALUE)).isEqualTo(500);
    }

    @Test
    void initialCreditsClientInitiatedUnidirectionalIsLimited() {
        int initialMaxData = 1000;
        int initialServerMaxStreamData = 500;
        int streamId = 6;  // Client-initiated uni: least significant two bits = 02

        // A client initiated stream is limited by the server's initial remote
        FlowControl fc = new FlowControl(initialMaxData, 9999, 9999, initialServerMaxStreamData);

        assertThat(fc.increaseFlowControlLimit(new QuicStream(streamId, conn, null), Long.MAX_VALUE)).isEqualTo(500);
    }

    @Test
    void streamsAreAllLimitedByTheSharedMaxData() {
        int initialMaxData = 900;
        int initialServerMaxStreamData = 500;
        int streamId1 = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream1 = new QuicStream(streamId1, conn, null);
        int streamId2 = 0;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream2 = new QuicStream(streamId2, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);

        assertThat(fc.increaseFlowControlLimit(stream1, 500)).isEqualTo(500);
        assertThat(fc.increaseFlowControlLimit(stream2, 500)).isEqualTo(400);
        assertThat(fc.increaseFlowControlLimit(stream1, 600)).isEqualTo(500);
        assertThat(fc.increaseFlowControlLimit(stream2, 600)).isEqualTo(400);
    }

    @Test
    void maxDataIncreasesStreamLimit() {
        int initialMaxData = 100;
        int initialServerMaxStreamData = 500;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);

        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(100);

        fc.process(new MaxDataFrame(300), PnSpace.App, null);
        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(300);

        fc.process(new MaxDataFrame(400), PnSpace.App, null);
        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(400);
    }

    @Test
    void maxDataIncreaseIsSharedBetweenStreams() {
        int initialMaxData = 300;
        int initialServerMaxStreamData = 1000;
        int streamId1 = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream1 = new QuicStream(streamId1, conn, null);
        int streamId2 = 0;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream2 = new QuicStream(streamId2, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);

        assertThat(fc.increaseFlowControlLimit(stream1, 200)).isEqualTo(200);
        assertThat(fc.increaseFlowControlLimit(stream2, 200)).isEqualTo(100);

        fc.process(new MaxDataFrame(600), PnSpace.App, null);
        assertThat(fc.increaseFlowControlLimit(stream1, 400)).isEqualTo(400);
        assertThat(fc.increaseFlowControlLimit(stream2, 400)).isEqualTo(200);
    }

    @Test
    void maxStreamDataIncreasesStreamLimit() {
        int initialMaxData = 500;
        int initialServerMaxStreamData = 100;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);

        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(100);

        fc.process(new MaxStreamDataFrame(streamId, 300), PnSpace.App, null);
        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(300);
    }

    @Test
    void waitForCreditsReturnsWhenMaxDataIsIncreased() throws InterruptedException {
        int initialMaxData = 100;
        int initialServerMaxStreamData = 500;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);

        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(100);

        int timeUntilMaxDataFrameIsReceived = 100;
        Instant start = Instant.now();
        executeAsyncWithDelay(() -> {
            // Receive MaxDataFrame that increments max data to 200
            fc.process(new MaxDataFrame(200), PnSpace.App, null);
        }, timeUntilMaxDataFrameIsReceived);

        fc.waitForFlowControlCredits(stream);
        Instant endWait = Instant.now();

        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(200);
        assertThat(Duration.between(start, endWait).toMillis()).isGreaterThan((long) (timeUntilMaxDataFrameIsReceived * 0.9));
    }

    @Test
    void waitForCreditsReturnsWhenMaxStreamDataIsIncreased() throws InterruptedException {
        int initialMaxData = 500;
        int initialServerMaxStreamData = 100;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);

        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(100);

        int timeUntilMaxDataFrameIsReceived = 100;
        Instant start = Instant.now();
        executeAsyncWithDelay(() -> {
            // Receive MaxStreamDataFrame that increments max data to 200
            fc.process(new MaxStreamDataFrame(streamId, 300), PnSpace.App, null);
        }, timeUntilMaxDataFrameIsReceived);

        fc.waitForFlowControlCredits(stream);
        Instant endWait = Instant.now();

        assertThat(fc.increaseFlowControlLimit(stream, 900)).isEqualTo(300);
        assertThat(Duration.between(start, endWait).toMillis()).isGreaterThan((long) (timeUntilMaxDataFrameIsReceived * 0.9));
    }

    @Test
    void waitForCreditsReturnsImmediatelyWhenCreditsAvailable() throws InterruptedException {
        int initialMaxData = 1000;
        int initialServerMaxStreamData = 500;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        assertThat(fc.increaseFlowControlLimit(stream, 100)).isEqualTo(100);

        fc.waitForFlowControlCredits(stream);
        assertThat(fc.increaseFlowControlLimit(stream, 200)).isEqualTo(200);
    }

    @Test
    void whenOutOfOrderMaxDataIsReceivedCurrentMaxDataIsNotReduced() {
        int initialMaxData = 500;
        int initialServerMaxStreamData = 2000;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(500);

        fc.process(new MaxDataFrame(1500), PnSpace.App, null);
        fc.process(new MaxDataFrame(1000), PnSpace.App, null);

        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(1500);
    }

    @Test
    void whenOutOfOrderMaxStreamDataIsReceivedCurrentMaxDataIsNotReduced() {
        int initialMaxData = 5000;
        int initialServerMaxStreamData = 500;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(500);

        fc.process(new MaxStreamDataFrame(1, 1500), PnSpace.App, null);
        fc.process(new MaxStreamDataFrame(1, 1000), PnSpace.App, null);

        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(1500);
    }

    @Test
    void updateInitialMaxData() {
        int initialMaxData = 1000;
        int initialServerMaxStreamData = 1500;
        int streamId = 1;  // arbitrary stream id, all initial limits are identical in this test
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
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
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(500);

        fc.process(new MaxDataFrame(1500), PnSpace.App, null);

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
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
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
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
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
    void updateInitialMaxStreamDataServerInitiatedBidirectionalStreamWithSmallerValueThanActual() {
        int initialMaxData = 5000;
        int initialServerMaxStreamData = 500;
        int streamId = 1;  // Server initiated bi-di
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(500);

        fc.process(new MaxStreamDataFrame(1, 1500), PnSpace.App, null);

        TransportParameters updateTransportParameters = new TransportParameters();
        updateTransportParameters.setInitialMaxData(initialMaxData);
        updateTransportParameters.setInitialMaxStreamDataUni(initialServerMaxStreamData);
        updateTransportParameters.setInitialMaxStreamDataBidiLocal(1000);   // This is the update
        updateTransportParameters.setInitialMaxStreamDataBidiRemote(initialServerMaxStreamData);
        fc.updateInitialValues(updateTransportParameters);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(1500);
    }

    @Test
    void updateInitialMaxStreamDataUnidirectionalStream() {
        int initialMaxData = 5000;
        int initialServerMaxStreamData = 500;
        int streamId = 2;  // Client initiated uni
        QuicStream stream = new QuicStream(streamId, conn, null);

        FlowControl fc = new FlowControl(initialMaxData, initialServerMaxStreamData, initialServerMaxStreamData, initialServerMaxStreamData);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(500);

        TransportParameters updateTransportParameters = new TransportParameters();
        updateTransportParameters.setInitialMaxData(initialMaxData);
        updateTransportParameters.setInitialMaxStreamDataUni(1000);
        updateTransportParameters.setInitialMaxStreamDataBidiLocal(initialServerMaxStreamData);   // This is the update
        updateTransportParameters.setInitialMaxStreamDataBidiRemote(initialServerMaxStreamData);
        fc.updateInitialValues(updateTransportParameters);
        assertThat(fc.increaseFlowControlLimit(stream, 1500)).isEqualTo(1000);
    }

    private void executeAsyncWithDelay(Runnable task, int delay) {
        executor.schedule(task, delay, TimeUnit.MILLISECONDS);
    }
}