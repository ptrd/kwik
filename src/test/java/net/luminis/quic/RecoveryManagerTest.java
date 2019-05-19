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
package net.luminis.quic;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.time.Duration;
import java.time.Instant;

import static org.mockito.Mockito.*;


class RecoveryManagerTest extends RecoveryTests {

    private RecoveryManager recoveryManager;
    private LostPacketHandler lostPacketHandler;
    private int defaultRtt = 40;
    private int defaultRttVar = 10;
    private ProbeSender probeSender;

    @BeforeEach
    void initObjectUnderTest() {
        RttEstimator rttEstimator = mock(RttEstimator.class);
        when(rttEstimator.getSmoothedRtt()).thenReturn(defaultRtt);
        when(rttEstimator.getLatestRtt()).thenReturn(defaultRtt);
        when(rttEstimator.getRttVar()).thenReturn(defaultRttVar);
        probeSender = mock(ProbeSender.class);
        recoveryManager = new RecoveryManager(rttEstimator, probeSender, mock(Logger.class));
    }

    @BeforeEach
    void initLostPacketCallback() {
        lostPacketHandler = mock(LostPacketHandler.class);
    }

    @AfterEach
    void shutdownRecoveryManager() {
        recoveryManager.shutdown();
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

        recoveryManager.onAckReceived(new AckFrame(2), EncryptionLevel.App);

        long startVerify = System.currentTimeMillis();
        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
        long endVerify = System.currentTimeMillis();
        System.out.println("Verify took " + (endVerify - startVerify) + " ms");  // Verify can take pretty long (especially when running in IDE), ruining the test when RTT is small.

        Thread.sleep(defaultRtt);

        verify(lostPacketHandler, times(1)).process(argThat(new PacketMatcher(1)));
    }

    @Test
    void whenAckElicitingPacketIsNotAckedProbeIsSent() throws InterruptedException {
        recoveryManager.packetSent(createPacket(2), Instant.now(), p -> {});

        int probeTimeout = defaultRtt + 4 * defaultRttVar;
        Thread.sleep(probeTimeout + 10);

        verify(probeSender, times(1)).sendProbe();
    }

    @Test
    void whenProbeIsNotAckedAnotherOneIsSent() throws InterruptedException {
        doAnswer(new Answer<Void>() {
            @Override
            public Void answer(InvocationOnMock invocationOnMock) throws Throwable {
                // Necessary to trigger setting the lastAckElicitingSent
                recoveryManager.packetSent(createPacket(3), Instant.now(), p -> {});
                return null;
            }
        }).when(probeSender).sendProbe();

        Instant firstPacketTime = Instant.now();
        recoveryManager.packetSent(createPacket(2), firstPacketTime, p -> {});

        int firstProbeTimeout = defaultRtt + 4 * defaultRttVar;
        Thread.sleep(firstProbeTimeout + 10);

        verify(probeSender, times(1)).sendProbe();

        int secondProbeTimeout = firstProbeTimeout * 2;
        long sleepTime = Duration.between(Instant.now(), firstPacketTime.plusMillis(firstProbeTimeout + secondProbeTimeout)).toMillis() - 20;
        Thread.sleep(sleepTime);
        verify(probeSender, times(1)).sendProbe();  // Not yet

        Thread.sleep(20 + 10);
        verify(probeSender, times(2)).sendProbe();  // Yet it should
    }

    @Test
    void noProbeIsSentForAck() throws InterruptedException {
        QuicPacket ackPacket = createPacket(8, new AckFrame(20));
        recoveryManager.packetSent(ackPacket, Instant.now(), p -> {});

        int probeTimeout = defaultRtt + 4 * defaultRttVar;

        Thread.sleep(probeTimeout + 10);

        verify(probeSender, never()).sendProbe();
    }

    @Test
    void whenAckElicitingPacketsAreNotAckedProbeIsSentForLastOnly() throws InterruptedException {
        int probeTimeout = defaultRtt + 4 * defaultRttVar;
        int delta = 10;
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
        verify(probeSender, times(1)).sendProbe();
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
        System.out.println("nu een ack op 10");
        // Ack on first packet, second packet must be the baseline for the probe-timeout
        recoveryManager.onAckReceived(new AckFrame(10), EncryptionLevel.App);

        // No Probe timeout yet!
        verify(probeSender, never()).sendProbe();

        Thread.sleep(probeTimeout / 2);
        // Now, second packet was sent more than probe-timeout ago, so now we should have a probe timeout
        verify(probeSender, times(1)).sendProbe();
    }
}
