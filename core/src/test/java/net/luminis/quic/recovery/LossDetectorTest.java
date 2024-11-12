/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.recovery;

import net.luminis.quic.cc.CongestionControlEventListener;
import net.luminis.quic.cc.CongestionController;
import net.luminis.quic.cc.NewRenoCongestionController;
import net.luminis.quic.common.EncryptionLevel;
import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.frame.ConnectionCloseFrame;
import net.luminis.quic.frame.Padding;
import net.luminis.quic.frame.PingFrame;
import net.luminis.quic.frame.Range;
import net.luminis.quic.impl.MockPacket;
import net.luminis.quic.impl.MoreArgumentMatchers;
import net.luminis.quic.impl.PacketMatcherByPacketNumber;
import net.luminis.quic.impl.Version;
import net.luminis.quic.log.NullLogger;
import net.luminis.quic.log.NullQLog;
import net.luminis.quic.packet.PacketInfo;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.test.FieldSetter;
import net.luminis.quic.test.TestClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;


class LossDetectorTest extends RecoveryTests {

    private LossDetector lossDetector;
    private LostPacketHandler lostPacketHandler;
    private int defaultRtt = 10;
    private CongestionController congestionController;
    private RttEstimator rttEstimator;
    private TestClock clock;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        clock = new TestClock();

        rttEstimator = mock(RttEstimator.class);
        when(rttEstimator.getSmoothedRtt()).thenReturn(defaultRtt);
        when(rttEstimator.getLatestRtt()).thenReturn(defaultRtt);
        congestionController = mock(CongestionController.class);
        lossDetector = new LossDetector(mock(RecoveryManager.class), rttEstimator, congestionController, () -> {}, new NullQLog());
        FieldSetter.setField(lossDetector, lossDetector.getClass().getDeclaredField("clock"), clock);
    }

    @BeforeEach
    void initLostPacketCallback() {
        lostPacketHandler = mock(LostPacketHandler.class);
    }

    //region congestion controller
    @Test
    void congestionControllerIsOnlyCalledOncePerAck() {
        List<QuicPacket> packets = createPackets(1, 2, 3);
        lossDetector.packetSent(packets.get(0), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(packets.get(1), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(packets.get(2), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(new Range(1L, 2L)), Instant.now());
        lossDetector.onAckReceived(new AckFrame(new Range(1L, 2L)), Instant.now());

        verify(congestionController, times(2)).registerAcked(any(List.class));
    }

    @Test
    void congestionControllerRegisterAckedNotCalledWithAckOnlyPacket() {
        QuicPacket packet = createPacket(1, new AckFrame(10));
        lossDetector.packetSent(packet, Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.onAckReceived(new AckFrame(1), Instant.now());

        verify(congestionController, times(1)).registerAcked(argThat(MoreArgumentMatchers.emptyList()));
    }

    @Test
    void congestionControllerRegisterLostNotCalledWithAckOnlyPacket() {
        QuicPacket packet = createPacket(1, new AckFrame(10));
        lossDetector.packetSent(packet, Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.onAckReceived(new AckFrame(4), Instant.now());

        verify(congestionController, times(0)).registerLost(anyList());
    }

    @Test
    void whenCongestionControllerIsClosedAllNonAckedPacketsShouldBeDiscarded() {
        lossDetector.packetSent(createPacket(0), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(1), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(2), Instant.now(), p -> {});

        lossDetector.onAckReceived(new AckFrame(0), Instant.now());

        lossDetector.close();
        verify(congestionController, times(1)).discard(argThat(l -> containsPackets(l, 1, 2)));
    }

    @Test
    void whenCongestionControllerIsClosedAllNotLostPacketsShouldBeDiscarded() {
        lossDetector.packetSent(createPacket(0), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(1), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(8), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(9), Instant.now(), p -> {});

        lossDetector.onAckReceived(new AckFrame(9), Instant.now());

        lossDetector.close();
        verify(congestionController, times(1)).discard(argThat(l -> containsPackets(l, 8)));
    }

    @Test
    void congestionControlStateDoesNotChangeWithUnrelatedAck() throws Exception {
        congestionController = new NewRenoCongestionController(new NullLogger(), mock(CongestionControlEventListener.class));
        setCongestionWindowSize(congestionController, 1240);
        FieldSetter.setField(lossDetector, LossDetector.class.getDeclaredField("congestionController"), congestionController);

        lossDetector.packetSent(new MockPacket(0, 12, EncryptionLevel.App, new PingFrame(), "packet 1"), Instant.now(), p -> {});
        lossDetector.packetSent(new MockPacket(1, 1200, EncryptionLevel.App, new PingFrame(), "packet 2"), Instant.now(), p -> {});
        lossDetector.packetSent(new MockPacket(2, 40, EncryptionLevel.App, new PingFrame(), "packet 1"), Instant.now(), p -> {});

        assertThat(congestionController.remainingCwnd()).isLessThan(1);

        // An ack on a non-existent packet, shouldn't change anything.
        lossDetector.onAckReceived(new AckFrame(0), Instant.now());

        assertThat(congestionController.remainingCwnd()).isLessThan(12 + 1);   // Because the 12 is acked, the cwnd is increased by 12 too.
    }

    @Test
    void congestionControlStateDoesNotChangeWithIncorrectAck() throws Exception {
        congestionController = new NewRenoCongestionController(new NullLogger(), mock(CongestionControlEventListener.class));
        setCongestionWindowSize(congestionController, 1240);
        FieldSetter.setField(lossDetector, LossDetector.class.getDeclaredField("congestionController"), congestionController);

        lossDetector.packetSent(new MockPacket(10, 1200, EncryptionLevel.App, new PingFrame(), "packet 1"), Instant.now(), p -> {});
        lossDetector.packetSent(new MockPacket(11, 1200, EncryptionLevel.App, new PingFrame(), "packet 2"), Instant.now(), p -> {});

        assertThat(congestionController.remainingCwnd()).isLessThan(1);

        // An ack on a non-existent packet, shouldn't change anything.
        lossDetector.onAckReceived(new AckFrame(3), Instant.now());

        assertThat(congestionController.remainingCwnd()).isLessThan(1);
    }
    //endregion

    //region declare lost
    @Test
    void withoutAcksNothingIsDeclaredLost() {
        int count = 10;
        Instant now = Instant.now();
        for (int i = 0; i < count; i++) {
            QuicPacket packet = createPacket(i);
            lossDetector.packetSent(packet, now.minusMillis(100 * (count - i)), lostPacket -> lostPacketHandler.process(lostPacket));
        }

        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
    }

    @Test
    void packetIsNotYetLostWhenTwoLaterPacketsAreAcked() {
        List<QuicPacket> packets = createPackets(1, 2, 3);
        lossDetector.packetSent(packets.get(0), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(packets.get(1), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(packets.get(2), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(new Range(1L, 2L)), Instant.now());

        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
    }

    @Test
    void packetIsLostWhenThreeLaterPacketsAreAcked() {
        List<QuicPacket> packets = createPackets(1, 2, 3, 4);
        lossDetector.packetSent(packets.get(0), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(packets.get(1), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(packets.get(2), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(packets.get(3), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(new Range(2L, 4L)), Instant.now());

        verify(lostPacketHandler, times(1)).process(argThat(new PacketMatcherByPacketNumber(1)));
    }

    @Test
    void ackOnlyPacketCannotBeDeclaredLost() {
        QuicPacket ackOnlyPacket = createPacket(1, new AckFrame());
        lossDetector.packetSent(ackOnlyPacket, Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));

        List<QuicPacket> packets = createPackets(2, 3, 4);
        packets.forEach(p ->
                lossDetector.packetSent(p, Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket)));

        lossDetector.onAckReceived(new AckFrame(new Range(2L, 4L)), Instant.now());

        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
    }

    @Test
    void packetTooOldIsDeclaredLost() {
        // Given second packets is sent (a little) more than 9/8 rtt
        int timeDiff = (defaultRtt * 9 / 8) + 1;
        lossDetector.packetSent(createPacket(6), clock.instant(), lostPacket -> lostPacketHandler.process(lostPacket));
        clock.fastForward(timeDiff);
        lossDetector.packetSent(createPacket(8), clock.instant(), lostPacket -> lostPacketHandler.process(lostPacket));

        // When when (only) the second packets is acked
        lossDetector.onAckReceived(new AckFrame(new Range(8L)), clock.instant());

        // Then the first is declared lost.
        verify(lostPacketHandler, times(1)).process(argThat(new PacketMatcherByPacketNumber(6)));
    }

    @Test
    void packetNotTooOldIsNotDeclaredLost() {
        Instant now = Instant.now();
        int timeDiff = defaultRtt - 1;  // Give some time for processing.
        lossDetector.packetSent(createPacket(6), now.minusMillis(timeDiff), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(8), now, lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(8L), Instant.now());

        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
    }

    @Test
    void oldPacketLaterThanLargestAcknowledgedIsNotDeclaredLost() {
        Instant now = Instant.now();
        int timeDiff = (defaultRtt * 9 / 8) + 10;
        lossDetector.packetSent(createPacket(1), now.minusMillis(timeDiff), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(3), now.minusMillis(timeDiff), lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(1L), Instant.now());

        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
    }

    @Test
    void packetNotYetLostIsLostAfterLossTime() throws Exception {
        // Given two packets are sent at the same time and only the last is acked, exactly after RTT
        lossDetector.packetSent(createPacket(6), clock.instant(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(8), clock.instant(), lostPacket -> lostPacketHandler.process(lostPacket));
        clock.fastForward(defaultRtt);
        lossDetector.onAckReceived(new AckFrame(8L), clock.instant());

        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
        assertThat(lossDetector.getLossTime()).isNotNull();

        // When time is progressing another 1/8 rtt and another ack is received
        clock.fastForward(defaultRtt / 8 + 1);
        lossDetector.onAckReceived(new AckFrame(9L), clock.instant());

        // Then the first packet is also acked (because by that time, it is old enough)
        verify(lostPacketHandler, times(1)).process(argThat(new PacketMatcherByPacketNumber(6)));
    }

    @Test
    void ifAllPacketsAreLostThenLossTimeIsNotSet() {
        Instant now = Instant.now();
        int timeDiff = (defaultRtt * 9 / 8) + 1;
        lossDetector.packetSent(createPacket(1), now.minusMillis(timeDiff), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(5), now, lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(8), now, lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(8L), Instant.now());

        assertThat(lossDetector.getLossTime()).isNull();
    }

    @Test
    void ifAllPacketsAreAckedThenLossTimeIsNotSet() {
        Instant now = Instant.now();
        int timeDiff = defaultRtt / 2;
        lossDetector.packetSent(createPacket(1), now.minusMillis(timeDiff), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(7), now, lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(8), now, lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(List.of(new Range(7L, 8L), new Range(1L))), Instant.now());
        assertThat(lossDetector.getLossTime()).isNull();
    }

    @Test
    void ifAllPacketsAreAckedBeforeLossTimeThenLossTimeIsNotSet() {
        Instant now = Instant.now();
        int timeDiff = defaultRtt / 2;
        lossDetector.packetSent(createPacket(1), now.minusMillis(timeDiff), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(7), now, lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(8), now, lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(List.of(new Range(8L), new Range(1L))), Instant.now());
        assertThat(lossDetector.getLossTime()).isNotNull();

        lossDetector.onAckReceived(new AckFrame(List.of(new Range(7L, 8L), new Range(1L))), Instant.now());

        assertThat(lossDetector.getLossTime()).isNull();
    }

    @Test
    void ackOnlyPacketShouldNotSetLossTime() {
        lossDetector.packetSent(createPacket(1, new AckFrame(1)), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(2), Instant.now(), p -> {});

        lossDetector.onAckReceived(new AckFrame(new Range(2L)), Instant.now());

        assertThat(lossDetector.getLossTime()).isNull();
    }
    //endregion

    //region acks
    @Test
    void detectUnacked() {
        lossDetector.packetSent(createPacket(2), Instant.now(), p -> {});

        assertThat(lossDetector.unAcked()).isNotEmpty();
    }

    @Test
    void ackedPacketIsNotDetectedAsUnacked() {
        lossDetector.packetSent(createPacket(2), Instant.now(), p -> {});
        lossDetector.onAckReceived(new AckFrame(2), Instant.now());

        assertThat(lossDetector.unAcked()).isEmpty();
    }

    @Test
    void lostPacketIsNotDetectedAsUnacked() throws Exception {
        // Given two packets sent
        lossDetector.packetSent(createPacket(2), clock.instant(), p -> {});
        lossDetector.packetSent(createPacket(3), clock.instant(), p -> {});

        // When after 2 rtt an Ack is received that will cause first packet to be lost
        clock.fastForward(defaultRtt * 2);
        lossDetector.onAckReceived(new AckFrame(3), clock.instant());  // So 2 will be lost.

        // Then the lost packet is not considered un-acknowlegded.
        assertThat(lossDetector.unAcked()).isEmpty();
    }

    @Test
    void nonAckElicitingIsNotDetectedAsUnacked() {
        lossDetector.packetSent(createPacket(2, new AckFrame(0)), Instant.now(), p -> {});

        assertThat(lossDetector.unAcked()).isEmpty();
    }

    @Test
    void testNoAckedReceivedWhenNoAckReceived() {
        lossDetector.packetSent(createPacket(2), Instant.now(), p -> {});

        assertThat(lossDetector.noAckedReceived()).isTrue();
    }

    @Test
    void testNoAckedReceivedWhenAckReceived() {
        lossDetector.packetSent(createPacket(0), Instant.now(), p -> {});
        lossDetector.onAckReceived(new AckFrame(0), Instant.now());

        assertThat(lossDetector.noAckedReceived()).isFalse();
    }

    @Test
    void testAckElicitingInFlightAcked() {
        lossDetector.packetSent(new MockPacket(10, 1200, EncryptionLevel.App, new PingFrame(), "packet 1"), Instant.now(), p -> {});
        lossDetector.packetSent(new MockPacket(11, 1200, EncryptionLevel.App, new Padding(10), "packet 2"), Instant.now(), p -> {});
        lossDetector.packetSent(new MockPacket(12, 1200, EncryptionLevel.App, new PingFrame(), "packet 2"), Instant.now(), p -> {});

        lossDetector.onAckReceived(new AckFrame(10), Instant.now());
        assertThat(lossDetector.ackElicitingInFlight()).isTrue();

        lossDetector.onAckReceived(new AckFrame(12), Instant.now());
        assertThat(lossDetector.ackElicitingInFlight()).isFalse();
    }

    @Test
    void testAckElicitingInFlightLost() {
        lossDetector.packetSent(new MockPacket(10, 1200, EncryptionLevel.App, new PingFrame(), "packet 1"), Instant.now(), p -> {});
        lossDetector.packetSent(new MockPacket(11, 1200, EncryptionLevel.App, new Padding(10), "packet 2"), Instant.now(), p -> {});
        lossDetector.packetSent(new MockPacket(15, 1200, EncryptionLevel.App, new PingFrame(), "packet 2"), Instant.now(), p -> {});

        lossDetector.onAckReceived(new AckFrame(15), Instant.now());

        assertThat(lossDetector.ackElicitingInFlight()).isFalse();
    }
    //endregion

    //region closed
    @Test
    void whenClosedNoPacketsAreUnacked() {
        lossDetector.packetSent(createPacket(2), Instant.now(), p -> {});
        lossDetector.close();

        assertThat(lossDetector.unAcked()).isEmpty();
    }

    @Test
    void whenClosedLossTimeIsUnset() {
        lossDetector.packetSent(createPacket(2), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(3), Instant.now(), p -> {});
        lossDetector.onAckReceived(new AckFrame(3), Instant.now());

        lossDetector.detectLostPackets();
        assertThat(lossDetector.getLossTime()).isNotNull();

        lossDetector.close();
        assertThat(lossDetector.getLossTime()).isNull();
    }

    @Test
    void whenClosedNoAckElicitingAreInFlight() {
        lossDetector.packetSent(createPacket(2), Instant.now(), p -> {});

        assertThat(lossDetector.ackElicitingInFlight()).isTrue();

        lossDetector.close();
        assertThat(lossDetector.ackElicitingInFlight()).isFalse();
    }
    //endregion

    //region bytes in flight
    @Test
    void packetWithConnectionCloseOnlyDoesNotIncreaseBytesInFlight() {
        lossDetector.packetSent(createPacket(0, new ConnectionCloseFrame(Version.getDefault())), Instant.now(), p -> {});
        verify(congestionController, never()).registerInFlight(any(QuicPacket.class));
    }

    @Test
    void ackPacketWithConnectionCloseOnlyDoesNotDecreaseBytesInFlight() {
        lossDetector.packetSent(createPacket(0, new ConnectionCloseFrame(Version.getDefault())), Instant.now(), p -> {});
        lossDetector.onAckReceived(new AckFrame(0), Instant.now());

        verify(congestionController, never()).registerAcked(argThat(l -> ! l.isEmpty()));   // It's okay when it is called with an empty list
    }

    @Test
    void lostPacketWithConnectionCloseOnlyDoesNotDecreaseBytesInFlight() {
        lossDetector.packetSent(createPacket(0, new ConnectionCloseFrame(Version.getDefault())), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(1, new ConnectionCloseFrame(Version.getDefault())), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(2, new ConnectionCloseFrame(Version.getDefault())), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(9, new ConnectionCloseFrame(Version.getDefault())), Instant.now(), p -> {});
        lossDetector.onAckReceived(new AckFrame(9), Instant.now());

        verify(congestionController, never()).registerLost(argThat(l -> ! l.isEmpty()));   // It's okay when it is called with an empty list
    }

    @Test
    void packetWithPaddingOnlyDoesIncreaseBytesInFlight() {
        lossDetector.packetSent(createPacket(0, new Padding(99)), Instant.now(), p -> {});
        verify(congestionController, times(1)).registerInFlight(any(QuicPacket.class));
    }

    @Test
    void lostPacketWithPaddingOnlyDoesNotDecreaseBytesInFlight() {
        lossDetector.packetSent(createPacket(0, new Padding(99)), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(1, new Padding(99)), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(2, new Padding(99)), Instant.now(), p -> {});
        lossDetector.packetSent(createPacket(9, new Padding(99)), Instant.now(), p -> {});
        lossDetector.onAckReceived(new AckFrame(9), Instant.now());

        verify(congestionController, atLeast(1)).registerLost(any(List.class));
    }
    //endregion

    //region helper methods
    // This test was used to reproduce a race condition in the LossDetector. It is of no use to run it in each build.
    // To check the test is actually testing the race condition, insert system.out.print's in reset and onAckReceived methods.
    // @Test
    void maybeReproduceRaceConditionInOnAckdReceived() throws InterruptedException {
        int numberOfTestRuns = 500;
        for (int tc = 1; tc <= numberOfTestRuns; tc++) {
            System.out.print("\n" + tc + ": ");
            final int testRun = tc;
            for (int i = 0; i < 10000; i++) {
                lossDetector.packetSent(new MockPacket(i, 100, "packet " + i), Instant.now(), p -> {});
            }
            Thread lossDetectorResetThread = new Thread(() -> {
                for (int i = 0; i < 1; i++) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {}
                    lossDetector.close();
                }
            });
            Thread onAckReceivedThread = new Thread(() -> {
                for (int i = 0; i < 100; i++) {
                    try {
                        lossDetector.onAckReceived(new AckFrame(i), Instant.now());
                    }
                    catch (Exception e) {
                        System.out.println("ERROR in test run " + testRun + ": " + e);
                        e.printStackTrace();
                        System.exit(1);
                    }
                }
            });
            onAckReceivedThread.start();
            lossDetectorResetThread.start();
            lossDetectorResetThread.join();
            onAckReceivedThread.join();
        }
    }

    private void setCongestionWindowSize(CongestionController congestionController, int cwnd) throws Exception {
        FieldSetter.setField(congestionController, congestionController.getClass().getSuperclass().getDeclaredField("congestionWindow"), cwnd);
    }

    private boolean containsPackets(List<? extends PacketInfo> packets, long... packetNumbers) {
        List<Long> listPacketNumbers = packets.stream().map(p -> p.packet().getPacketNumber()).collect(Collectors.toList());
        for (long pn: packetNumbers) {
            if (! listPacketNumbers.contains(pn)) {
                return false;
            }
        }
        return true;
    }
    //endregion
}
