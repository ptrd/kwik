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
package net.luminis.quic.recovery;

import net.luminis.quic.*;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.recovery.LossDetector;
import net.luminis.quic.recovery.RecoveryManager;
import net.luminis.quic.recovery.RecoveryTests;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.internal.util.reflection.FieldSetter;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;


class RecoveryManagerTest extends RecoveryTests {

    private RecoveryManager recoveryManager;
    private LostPacketHandler lostPacketHandler;
    private int defaultRtt = 80;
    private int defaultRttVar = defaultRtt / 4;
    private int epsilon = defaultRtt / 4;  // A small value to check for events that should occur at a specified time; the epsilon is the variance allowed.
    private ProbeSender probeSender;
    private RttEstimator rttEstimator;

    @BeforeEach
    void initObjectUnderTest() {
        rttEstimator = mock(RttEstimator.class);
        when(rttEstimator.getSmoothedRtt()).thenReturn(defaultRtt);
        when(rttEstimator.getLatestRtt()).thenReturn(defaultRtt);
        when(rttEstimator.getRttVar()).thenReturn(defaultRttVar);
        probeSender = mock(ProbeSender.class);
        Logger logger = mock(Logger.class);
        // logger = new SysOutLogger();
        // logger.logRecovery(true);
        recoveryManager = new RecoveryManager(mock(FrameProcessorRegistry.class), rttEstimator, mock(CongestionController.class), probeSender, logger);
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
    void nonAckedPacketThatCannotYetBeDeclaredLostIsLostAfterLossTime() throws InterruptedException {

        Instant now = Instant.now();
        recoveryManager.packetSent(createPacket(1), now.minusMillis(defaultRtt / 2), lostPacket -> lostPacketHandler.process(lostPacket));
        recoveryManager.packetSent(createPacket(2), now, p -> {});

        recoveryManager.onAckReceived(new AckFrame(2), PnSpace.App);

        long startVerify = System.currentTimeMillis();
        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
        long endVerify = System.currentTimeMillis();
        System.out.println("Verify took " + (endVerify - startVerify) + " ms");  // Verify can take pretty long (especially when running in IDE), ruining the test when RTT is small.

        Thread.sleep(defaultRtt);

        verify(lostPacketHandler, times(1)).process(argThat(new PacketMatcherByPacketNumber(1)));
    }

    @Test
    void whenAckElicitingPacketIsNotAckedProbeIsSent() throws InterruptedException {
        recoveryManager.packetSent(createPacket(2), Instant.now(), p -> {});

        int probeTimeout = defaultRtt + 4 * defaultRttVar;
        Thread.sleep(probeTimeout + epsilon);

        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));
    }

    @Test
    void whenProbeIsNotAckedAnotherOneIsSent() throws InterruptedException {
        mockSendingProbe(3, 4);

        Instant firstPacketTime = Instant.now();
        recoveryManager.packetSent(createPacket(2), firstPacketTime, p -> {});

        int firstProbeTimeout = defaultRtt + 4 * defaultRttVar;
        Thread.sleep(firstProbeTimeout + epsilon);

        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));
        Instant firstProbeSentTime = Instant.now();

        int secondProbeTimeout = firstProbeTimeout * 2;
        long sleepTime = Duration.between(Instant.now(), firstPacketTime.plusMillis(firstProbeTimeout + secondProbeTimeout)).toMillis() - 2 * epsilon;
        Thread.sleep(sleepTime);
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));  // Not yet

        sleepTime = Duration.between(firstProbeSentTime, Instant.now().plusMillis(secondProbeTimeout)).toMillis();
        Thread.sleep(sleepTime);
        verify(probeSender, times(3)).sendProbe(anyList(), any(EncryptionLevel.class));  // Yet it should, and 2 probes are sent simultaneously
    }

    @Test
    void noProbeIsSentForAck() throws InterruptedException {
        // Simulate peer has completed address validation
        recoveryManager.onAckReceived(new AckFrame(0), PnSpace.App);

        QuicPacket ackPacket = createPacket(8, new AckFrame(20));
        recoveryManager.packetSent(ackPacket, Instant.now(), p -> {});

        int probeTimeout = defaultRtt + 4 * defaultRttVar;

        Thread.sleep(probeTimeout + 5 * epsilon);  // Because checking for "never", use large epsilon

        verify(probeSender, never()).sendProbe();
    }

    @Test
    void whenAckElicitingPacketsAreNotAckedProbeIsSentForLastOnly() throws InterruptedException {
        int probeTimeout = defaultRtt + 4 * defaultRttVar;
        int delta = epsilon;
        recoveryManager.packetSent(createPacket(10), Instant.now(), p -> {});
        Thread.sleep(probeTimeout - delta);
        recoveryManager.packetSent(createPacket(11), Instant.now(), p -> {});
        Thread.sleep(probeTimeout - delta);
        recoveryManager.packetSent(createPacket(12), Instant.now(), p -> {});
        Thread.sleep(probeTimeout - delta);
        recoveryManager.packetSent(createPacket(13), Instant.now(), p -> {});
        Thread.sleep(probeTimeout - delta);
        recoveryManager.packetSent(createPacket(14), Instant.now(), p -> {});
        Thread.sleep(probeTimeout - delta);
        recoveryManager.packetSent(createPacket(15), Instant.now(), p -> {});

        verify(probeSender, never()).sendProbe();
        Thread.sleep(probeTimeout + delta);
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));
    }

    @Test
    void probeTimeoutShouldMoveToLastAckEliciting() throws InterruptedException {
        int probeTimeout = defaultRtt + 4 * defaultRttVar;

        // First ack-eliciting
        recoveryManager.packetSent(createPacket(10), Instant.now(), p -> {});

        Thread.sleep(probeTimeout / 2);
        // Second ack-eliciting
        recoveryManager.packetSent(createPacket(11), Instant.now(), p -> {});

        Thread.sleep(probeTimeout / 2);
        // Ack on first packet, second packet must be the baseline for the probe-timeout
        recoveryManager.onAckReceived(new AckFrame(10), PnSpace.App);

        // No Probe timeout yet!
        Thread.sleep(epsilon);
        verify(probeSender, never()).sendProbe();

        Thread.sleep(probeTimeout / 2);
        // Now, second packet was sent more than probe-timeout ago, so now we should have a probe timeout
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));
    }

    @Test
    void whenProbesAreAckedProbeTimeoutIsResetToNormal() throws InterruptedException {
        mockSendingProbe(3, 4, 5);
        // Simulate a round trip to get rid of peer awaiting address validation
        recoveryManager.packetSent(createPacket(1), Instant.now(), p -> {});
        recoveryManager.onAckReceived(new AckFrame(1), PnSpace.App);
        clearInvocations(probeSender);

        Instant firstPacketTime = Instant.now();
        recoveryManager.packetSent(createPacket(2), firstPacketTime, p -> {});

        int firstProbeTimeout = defaultRtt + 4 * defaultRttVar;
        Thread.sleep(firstProbeTimeout + epsilon);

        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));

        int secondProbeTimeout = firstProbeTimeout * 2;
        long sleepTime = Duration.between(Instant.now(), firstPacketTime.plusMillis(firstProbeTimeout + secondProbeTimeout)).toMillis() - 2 * epsilon;
        Thread.sleep(sleepTime);
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));  // Not yet

        Thread.sleep(2 * epsilon + 1 * epsilon);
        verify(probeSender, times(3)).sendProbe(anyList(), any(EncryptionLevel.class));  // Yet it should, and 2 probes simultaneously

        // Receive Ack, should reset PTO count
        recoveryManager.onAckReceived(new AckFrame(3), PnSpace.App);

        recoveryManager.packetSent(createPacket(5), Instant.now(), p -> {});

        Thread.sleep(firstProbeTimeout + epsilon);

        verify(probeSender, times(4)).sendProbe(anyList(), any(EncryptionLevel.class));
    }

    @Test
    void earliestLossTimeIsFound() throws Exception {
        LossDetector[] detectors = new LossDetector[3];
        FieldSetter.setField(recoveryManager, recoveryManager.getClass().getDeclaredField("lossDetectors"), detectors);

        for (int i = 0; i < 3; i++) {
            detectors[i] = mock(LossDetector.class);
        }

        Instant someInstant = Instant.now();
        when(detectors[0].getLossTime()).thenReturn(someInstant);
        when(detectors[1].getLossTime()).thenReturn(null);
        when(detectors[2].getLossTime()).thenReturn(someInstant.minusMillis(100));

        assertThat(recoveryManager.getEarliestLossTime(LossDetector::getLossTime).pnSpace.ordinal()).isEqualTo(2);
    }

    @Test
    void initialPacketRetransmit() throws InterruptedException {

        Instant firstPacketTime = Instant.now();
        recoveryManager.packetSent(createCryptoPacket(0), firstPacketTime, lostPacket -> lostPacketHandler.process(lostPacket));
        Duration delay = Duration.between(firstPacketTime, Instant.now());

        Thread.sleep(((int) (defaultRtt * 1.8)) - delay.toMillis());
        verify(probeSender, times(0)).sendProbe(anyList(), any(EncryptionLevel.class));

        Thread.sleep(((int) (defaultRtt * 0.2)) + delay.toMillis() + epsilon);
        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));

        verify(lostPacketHandler, times(0)).process(any(InitialPacket.class));
    }

    @Test
    void probeIsSentToPeerAwaitingAddressValidation() throws InterruptedException {
        Instant firstPacketTime = Instant.now();
        recoveryManager.packetSent(createCryptoPacket(0), firstPacketTime, lostPacket -> {});

        Thread.sleep((int) defaultRtt);
        recoveryManager.onAckReceived(new AckFrame(0), PnSpace.Initial);

        int probeTimeout = defaultRtt + 4 * defaultRttVar;
        Thread.sleep(probeTimeout + epsilon);

        verify(probeSender, times(1)).sendProbe(anyList(), any(EncryptionLevel.class));
    }

    @Test
    void framesToRetransmitShouldNotBePing() throws Exception {
        QuicPacket pingPacket = createHandshakePacket(0, new PingFrame());
        recoveryManager.packetSent(pingPacket, Instant.now(), p -> {});
        QuicPacket handshakePacket = createHandshakePacket(1, new CryptoFrame(Version.getDefault(), new byte[100]));
        recoveryManager.packetSent(handshakePacket, Instant.now(), p -> {});

        List<QuicFrame> framesToRetransmit = recoveryManager.getFramesToRetransmit(PnSpace.Handshake);

        assertThat(framesToRetransmit).isNotEmpty();
        assertThat(framesToRetransmit).doesNotHaveAnyElementsOfTypes(PingFrame.class);
        assertThat(framesToRetransmit).hasAtLeastOneElementOfType(CryptoFrame.class);
    }

    @Test
    void framesToRetransmitShouldNotBePingAndPaddingAndAck() throws Exception {
        QuicPacket pingPacket = createHandshakePacket(0, new PingFrame(), new Padding(2), new AckFrame(0));
        recoveryManager.packetSent(pingPacket, Instant.now(), p -> {});
        QuicPacket handshakePacket = createHandshakePacket(1, new CryptoFrame(Version.getDefault(), new byte[100]));
        recoveryManager.packetSent(handshakePacket, Instant.now(), p -> {});

        List<QuicFrame> framesToRetransmit = recoveryManager.getFramesToRetransmit(PnSpace.Handshake);

        assertThat(framesToRetransmit).isNotEmpty();
        assertThat(framesToRetransmit).doesNotHaveAnyElementsOfTypes(PingFrame.class);
        assertThat(framesToRetransmit).hasAtLeastOneElementOfType(CryptoFrame.class);
    }

    private void mockSendingProbe(int... packetNumbers) {
        doAnswer(new Answer<Void>() {
            private int count;

            @Override
            public Void answer(InvocationOnMock invocationOnMock) throws Throwable {
                // Necessary to trigger setting the lastAckElicitingSent, which normally happens when a real probe is sent.
                int packetNumber = count < packetNumbers.length? packetNumbers[count++]: 666;
                recoveryManager.packetSent(createPacket(packetNumber), Instant.now(), p -> {});
                return null;
            }
        }).when(probeSender).sendProbe(anyList(), any(EncryptionLevel.class));
    }
}
