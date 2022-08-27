/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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

import net.luminis.quic.*;
import net.luminis.quic.cc.CongestionController;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.qlog.QLog;
import net.luminis.quic.send.Sender;
import net.luminis.quic.test.TestClock;
import net.luminis.quic.test.TestScheduledExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import net.luminis.quic.test.FieldSetter;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;


class RecoveryManagerTest extends RecoveryTests {

    private RecoveryManager recoveryManager;
    private LostPacketHandler lostPacketHandler;
    private int defaultRtt = 80;
    private int defaultRttVar = defaultRtt / 4;
    private Sender probeSender;
    private RttEstimator rttEstimator;
    private TestClock clock;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        rttEstimator = mock(RttEstimator.class);
        when(rttEstimator.getSmoothedRtt()).thenReturn(defaultRtt);
        when(rttEstimator.getLatestRtt()).thenReturn(defaultRtt);
        when(rttEstimator.getRttVar()).thenReturn(defaultRttVar);
        probeSender = mock(Sender.class);
        Logger logger = mock(Logger.class);
        when(logger.getQLog()).thenReturn(mock(QLog.class));
        // logger = new SysOutLogger();
        // logger.logRecovery(true);
        clock = new TestClock();
        recoveryManager = new RecoveryManager(clock, mock(FrameProcessorRegistry.class), Role.Client, rttEstimator, mock(CongestionController.class), probeSender, logger);
        ScheduledExecutorService scheduler = new TestScheduledExecutor(clock);
        FieldSetter.setField(recoveryManager, recoveryManager.getClass().getDeclaredField("scheduler"), scheduler);
    }

    @BeforeEach
    void initLostPacketCallback() {
        lostPacketHandler = mock(LostPacketHandler.class);
    }

    @AfterEach
    void shutdownRecoveryManager() {
        recoveryManager.stopRecovery();
    }

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-20#section-6.1.2
    // "If packets sent prior to the largest
    //   acknowledged packet cannot yet be declared lost, then a timer SHOULD
    //   be set for the remaining time."
    @Test
    void nonAckedPacketThatCannotYetBeDeclaredLostIsLostAfterLossTime() {
        // Given two packets sent, with half RTT interval
        recoveryManager.packetSent(createPacket(1), clock.instant(), lostPacketHandler::process);
        clock.fastForward(defaultRtt / 2);
        recoveryManager.packetSent(createPacket(2), clock.instant(), this::noOp);

        // When an ack is received immediately (impossible in reality, but fine for a test)
        recoveryManager.onAckReceived(new AckFrame(2), PnSpace.App, clock.instant());

        // Then only after some time (1 RTT), the packet is lost
        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
        clock.fastForward(defaultRtt);
        verify(lostPacketHandler, times(1)).process(argThat(new PacketMatcherByPacketNumber(1)));
    }

    @Test
    void whenAckElicitingPacketIsNotAckedProbeIsSent() {
        // Given recovery manager is not in handshake state anymore
        recoveryManager.handshakeStateChangedEvent(HandshakeState.Confirmed);

        // When packet is set
        recoveryManager.packetSent(createPacket(2), clock.instant(), this::noOp);

        // Then only after probe timeout, a probe has been sent.
        int probeTimeout = defaultRtt + 4 * defaultRttVar;
        clock.fastForward(probeTimeout * 9 / 10);
        verify(probeSender, never()).sendProbe(anyList(), any(EncryptionLevel.class));
        clock.fastForward(probeTimeout * 1 / 10);
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));
    }

    @Test
    void whenProbeIsNotAckedAnotherOneIsSent() {
        // Given recovery manager is not in handshake state anymore and when probes are sent, packetSent() is called
        recoveryManager.handshakeStateChangedEvent(HandshakeState.Confirmed);
        ensureSendProbeCallsPacketSent(3, 4, 5);

        // When a packet is sent but not acked
        Instant firstPacketTime = clock.instant();
        recoveryManager.packetSent(createPacket(2), firstPacketTime, p -> {});

        // After probe timeout time, the first probe is sent
        int firstProbeTimeout = defaultRtt + 4 * defaultRttVar;
        clock.fastForward(firstProbeTimeout);
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));

        // Then only after 2nd probe timeout, a second and third probe are sent.
        int secondProbeTimeout = firstProbeTimeout * 2;
        clock.fastForward(secondProbeTimeout * 9 / 10);
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));  // Not yet
        clock.fastForward(secondProbeTimeout * 1 / 10);
        verify(probeSender, times(3)).sendProbe(anyList(), any(EncryptionLevel.class));  // Yet it should, and 2 probes are sent simultaneously
    }

    @Test
    void noProbeIsSentForAck() {
        // Given peer has completed address validation
        recoveryManager.onAckReceived(new AckFrame(0), PnSpace.App, Instant.now());

        // When sending a packet that is not ack-eliciting
        QuicPacket ackPacket = createPacket(8, new AckFrame(20));
        recoveryManager.packetSent(ackPacket, Instant.now(), p -> {});

        // Then after probe timeout, no probe is sent, not even after 10 times probe timeout a probe is sent.
        int probeTimeout = defaultRtt + 4 * defaultRttVar;
        clock.fastForward(probeTimeout * 10);
        verify(probeSender, never()).sendProbe(EncryptionLevel.App);
    }

    @Test
    void whenAckElicitingPacketsAreNotAckedProbeIsSentForLastOnly() {
        // Given recovery manager is not in handshake state anymore
        recoveryManager.handshakeStateChangedEvent(HandshakeState.Confirmed);

        // When multiple packets are sent, with interval smaller than probe timeout
        int probeTimeout = defaultRtt + 4 * defaultRttVar;
        int interval = probeTimeout / 2;
        recoveryManager.packetSent(createPacket(10), clock.instant(), p -> {});
        clock.fastForward(interval);
        recoveryManager.packetSent(createPacket(11), clock.instant(), p -> {});
        clock.fastForward(interval);
        recoveryManager.packetSent(createPacket(12), clock.instant(), p -> {});
        clock.fastForward(interval);
        recoveryManager.packetSent(createPacket(13), clock.instant(), p -> {});
        clock.fastForward(interval);
        recoveryManager.packetSent(createPacket(14), clock.instant(), p -> {});
        clock.fastForward(interval);
        recoveryManager.packetSent(createPacket(15), clock.instant(), p -> {});

        // Then, finally, only one probe is sent, <probe timeout> time after last packet
        verify(probeSender, never()).sendProbe(anyList(), any(EncryptionLevel.class));
        clock.fastForward(probeTimeout);
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));
    }

    @Test
    void probeTimeoutShouldMoveToLastAckEliciting() {
        // Given recovery manager is not in handshake state anymore
        recoveryManager.handshakeStateChangedEvent(HandshakeState.Confirmed);
        int probeTimeout = defaultRtt + 4 * defaultRttVar;

        // When two (ack-eliciting) packets are sent, with some time in between,
        // and the first is acked some time later
        recoveryManager.packetSent(createPacket(10), clock.instant(), p -> {});
        clock.fastForward(probeTimeout / 2);
        recoveryManager.packetSent(createPacket(11), clock.instant(), p -> {});
        clock.fastForward(probeTimeout / 2);
        // Ack on first packet, second packet must be the baseline for the probe-timeout
        recoveryManager.onAckReceived(new AckFrame(10), PnSpace.App, Instant.now());

        // Then, a probe should be sent <probe timeout> time after the second packet was sent
        // (which is now 1/2 probeTimeout in the past, so after 1/2 probeTimeout, the probe should be sent)
        clock.fastForward(probeTimeout * 3 / 8);
        verify(probeSender, never()).sendProbe(EncryptionLevel.App);
        clock.fastForward(probeTimeout * 1 / 8);
        // Now, second packet was sent more than probe-timeout ago, so now we should have a probe timeout
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));
    }

    @Test
    void whenProbesAreAckedProbeTimeoutIsResetToNormal() throws InterruptedException {
        // Given recovery manager is not in handshake state anymore and when probes are sent, packetSent() is called
        recoveryManager.handshakeStateChangedEvent(HandshakeState.Confirmed);
        ensureSendProbeCallsPacketSent(3, 4, 5);

        // And a packet was sent and not acked, so
        recoveryManager.packetSent(createPacket(2), clock.instant(), p -> {});

        // A first probe
        int firstProbeTimeout = defaultRtt + 4 * defaultRttVar;
        clock.fastForward(firstProbeTimeout);
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));
        clearInvocations(probeSender);

        // And a second probe are sent
        int secondProbeTimeout = firstProbeTimeout * 2;
        clock.fastForward(secondProbeTimeout);
        verify(probeSender, times(2)).sendProbe(anyList(), any(EncryptionLevel.class));  // Yet it should, and 2 probes simultaneously
        clearInvocations(probeSender);

        // When an ack is received (on the first probe)
        recoveryManager.onAckReceived(new AckFrame(3), PnSpace.App, clock.instant());

        // Then the probe timeout is reset to the value of the first probe timeout (the exponential multiplier is reset)
        clock.fastForward(firstProbeTimeout * 7 / 8);
        verify(probeSender, never()).sendProbe(anyList(), any(EncryptionLevel.class));
        clock.fastForward(firstProbeTimeout * 1 / 8);
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));
    }

    @Test
    void earliestLossTimeIsFound() throws Exception {
        // Given mock loss detectors are instantiated and registered in the recovery manager
        LossDetector[] detectors = new LossDetector[3];
        for (int i = 0; i < 3; i++) {
            detectors[i] = mock(LossDetector.class);
        }
        FieldSetter.setField(recoveryManager, recoveryManager.getClass().getDeclaredField("lossDetectors"), detectors);

        Instant someInstant = Instant.now();
        when(detectors[0].getLossTime()).thenReturn(someInstant);
        when(detectors[1].getLossTime()).thenReturn(null);
        when(detectors[2].getLossTime()).thenReturn(someInstant.minusMillis(100));

        // When earliest loss time is determined
        // Then the value of the earliest is returned
        assertThat(recoveryManager.getEarliestLossTime(LossDetector::getLossTime).pnSpace.ordinal()).isEqualTo(2);
    }

    @Test
    void initialPacketRetransmit() {
        // Given an initial packet is sent (with crypto frames only)
        recoveryManager.packetSent(createCryptoPacket(0), clock.instant(), lostPacket -> lostPacketHandler.process(lostPacket));

        // When the first probe is sent
        int firstProbeTimeout = defaultRtt + 4 * defaultRttVar;
        clock.fastForward(firstProbeTimeout * 7 / 8);
        verify(probeSender, times(0)).sendProbe(anyList(), any(EncryptionLevel.class));
        clock.fastForward(firstProbeTimeout * 1 / 8);
        // Then the probe contains (retransmitted) crypto frames
        verify(probeSender, times(1)).sendProbe(argThat(frames -> frames.stream().allMatch(f -> f instanceof CryptoFrame)), any(EncryptionLevel.class));
        // And the lost packet handler is not called (because that would lead to an additional retransmit: the probe is the retransmit)
        verify(lostPacketHandler, never()).process(any(InitialPacket.class));
    }

    @Test
    void probeIsSentToPeerAwaitingAddressValidation() throws InterruptedException {
        // Given a client sends an initial packet that is acknowledged
        recoveryManager.packetSent(createCryptoPacket(0), clock.instant(), lostPacket -> {});
        clock.fastForward(defaultRtt);
        recoveryManager.onAckReceived(new AckFrame(0), PnSpace.Initial, clock.instant());

        // When nothing is received during first probe timeout
        int probeTimeout = defaultRtt + 4 * defaultRttVar;
        clock.fastForward(probeTimeout);

        // Then even though all client packets are acked, it sends to a probe to prevent a deadlock when server cannot send due to the amplification limit
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));
    }

    @Test
    void framesToRetransmitShouldNotBePing() throws Exception {
        QuicPacket pingPacket = createHandshakePacket(0, new PingFrame());
        recoveryManager.packetSent(pingPacket, clock.instant(), p -> {});
        QuicPacket handshakePacket = createHandshakePacket(1, new CryptoFrame(Version.getDefault(), new byte[100]));
        recoveryManager.packetSent(handshakePacket, clock.instant(), p -> {});

        List<QuicFrame> framesToRetransmit = recoveryManager.getFramesToRetransmit(PnSpace.Handshake);

        assertThat(framesToRetransmit).isNotEmpty();
        assertThat(framesToRetransmit).doesNotHaveAnyElementsOfTypes(PingFrame.class);
        assertThat(framesToRetransmit).hasAtLeastOneElementOfType(CryptoFrame.class);
    }

    @Test
    void framesToRetransmitShouldNotBePingAndPaddingAndAck() throws Exception {
        QuicPacket pingPacket = createHandshakePacket(0, new PingFrame(), new Padding(2), new AckFrame(0));
        recoveryManager.packetSent(pingPacket, clock.instant(), p -> {});
        QuicPacket handshakePacket = createHandshakePacket(1, new CryptoFrame(Version.getDefault(), new byte[100]));
        recoveryManager.packetSent(handshakePacket, clock.instant(), p -> {});

        List<QuicFrame> framesToRetransmit = recoveryManager.getFramesToRetransmit(PnSpace.Handshake);

        assertThat(framesToRetransmit).isNotEmpty();
        assertThat(framesToRetransmit).doesNotHaveAnyElementsOfTypes(PingFrame.class);
        assertThat(framesToRetransmit).hasAtLeastOneElementOfType(CryptoFrame.class);
    }

    /**
     * Ensure that packetSent is called when probes packets are sent with the given packetNumbers.
     * In production code, packetSent is called by the sender, when it actually sends a packet.
     * This method hooks in onto sender's sendProbe method, calling packetSent when sendProbe is called.
     * @param packetNumbers
     */
    private void ensureSendProbeCallsPacketSent(int... packetNumbers) {
        doAnswer(new Answer<Void>() {
            private int count;

            @Override
            public Void answer(InvocationOnMock invocationOnMock) throws Throwable {
                // Necessary to trigger setting the lastAckElicitingSent, which normally happens when a real packet is sent.
                int packetNumber = count < packetNumbers.length? packetNumbers[count++]: 666;
                recoveryManager.packetSent(createPacket(packetNumber), clock.instant(), p -> {});
                return null;
            }
        }).when(probeSender).sendProbe(anyList(), any(EncryptionLevel.class));
    }

    void noOp(QuicPacket lostPacket) {}
}
