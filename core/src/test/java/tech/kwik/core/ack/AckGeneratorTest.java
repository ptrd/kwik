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
package tech.kwik.core.ack;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.frame.AckFrame;
import tech.kwik.core.frame.Range;
import tech.kwik.core.impl.MockPacket;
import tech.kwik.core.impl.Version;
import tech.kwik.core.packet.RetryPacket;
import tech.kwik.core.packet.VersionNegotiationPacket;
import tech.kwik.core.recovery.RttProvider;
import tech.kwik.core.send.Sender;
import tech.kwik.core.test.TestClock;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class AckGeneratorTest {

    private TestClock clock;
    private AckGenerator ackGenerator;
    private Sender sender;
    private RttProvider rttProvider;

    @BeforeEach
    void initObjectUnderTest() {
        clock = new TestClock();
        sender = mock(Sender.class);
        rttProvider = mock(RttProvider.class);
        ackGenerator = new AckGenerator(clock, PnSpace.App, sender, rttProvider);
    }

    @Test
    void newGeneratorDoesNotGenerateAck() {
        assertThat(ackGenerator.hasAckToSend()).isEqualTo(false);
    }

    @Test
    void receivingPacketLeadsToSingleAck() {
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));
        assertThat(ackGenerator.hasAckToSend()).isEqualTo(true);

        AckFrame ack = ackGenerator.generateAckForPacket(0).get();

        assertThat(ack.getLargestAcknowledged()).isEqualTo(0);
        assertThat(ack.getAckedPacketNumbers()).containsOnly(0L);
    }

    @Test
    void receivingMultipleConsequetivePacketLeadsToRangeAck() {
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(1, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(2, 83, EncryptionLevel.Initial));

        assertThat(ackGenerator.hasAckToSend()).isEqualTo(true);

        AckFrame ack = ackGenerator.generateAckForPacket(0).get();

        assertThat(ack.getLargestAcknowledged()).isEqualTo(2);
        assertThat(ack.getAckedPacketNumbers()).containsOnly(0L, 1L, 2L);
    }

    @Test
    void afterReceivingMorePacketsOldAcksRemain() {
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(1, 83, EncryptionLevel.Initial));

        AckFrame ack1 = ackGenerator.generateAckForPacket(1).get();
        assertThat(ack1.getAckedPacketNumbers()).containsOnly(0L, 1L);

        ackGenerator.packetReceived(new MockPacket(3, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(5, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(6, 83, EncryptionLevel.Initial));

        AckFrame ack2 = ackGenerator.generateAckForPacket(1).get();

        assertThat(ack2.getLargestAcknowledged()).isEqualTo(6);
        assertThat(ack2.getAckedPacketNumbers()).containsOnly(0L, 1L, 3L, 5L, 6L);
    }

    @Test
    void afterProcessingReceivedAckForAllSentAcksThereAreNoAcksToSend() {
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(1, 83, EncryptionLevel.Initial));

        AckFrame ack1 = ackGenerator.generateAckForPacket(1).get();
        assertThat(ack1.getAckedPacketNumbers()).containsOnly(0L, 1L);

        ackGenerator.process(new AckFrame(1));

        assertThat(ackGenerator.hasAckToSend()).isEqualTo(false);
    }

    @Test
    void afterProcessingReceivedAckAcknowledgedAcksAreRemoved() {
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(1, 83, EncryptionLevel.Initial));

        AckFrame ack1 = ackGenerator.generateAckForPacket(6).get();
        assertThat(ack1.getAckedPacketNumbers()).containsOnly(0L, 1L);

        ackGenerator.process(new AckFrame(6));  // This acks the ack sent in packet 6 -> ack1
        ackGenerator.packetReceived(new MockPacket(2, 83, EncryptionLevel.Initial));

        assertThat(ackGenerator.hasAckToSend()).isEqualTo(true);

        AckFrame ack2 = ackGenerator.generateAckForPacket(2).get();
        assertThat(ack2.getAckedPacketNumbers()).containsOnly(2L);
    }

    @Test
    void receivingVersionNegotiationPacketDoesNotLeadToAck() {
        ackGenerator.packetReceived(new VersionNegotiationPacket());

        assertThat(ackGenerator.hasAckToSend()).isEqualTo(false);
    }

    @Test
    void receivingRetryPacketDoesNotLeadToAck() {
        ackGenerator.packetReceived(new RetryPacket(Version.getDefault()));

        assertThat(ackGenerator.hasAckToSend()).isEqualTo(false);
    }

    @Test
    void afterSendingAckThereIsNoNewAckToSend() throws Exception {
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));
        assertThat(ackGenerator.hasNewAckToSend()).isEqualTo(true);

        AckFrame ack = ackGenerator.generateAckForPacket(0).get();

        assertThat(ackGenerator.hasNewAckToSend()).isEqualTo(false);
    }

    @Test
    void ifTheNotAcknowledgedPacketIsAckOnlyThereIsNowAckNewToSend() throws Exception {
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial, new AckFrame()));
        assertThat(ackGenerator.hasNewAckToSend()).isEqualTo(false);
    }

    @Test
    void ifAckIsDelayedTheDelayFieldIsSet() throws Exception {
        // Given
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));

        // When
        clock.fastForward(10);

        // Then
        AckFrame ackFrame = ackGenerator.generateAckForPacket(13).get();
        assertThat(ackFrame.getAckDelay()).isGreaterThanOrEqualTo(10);
    }

    @Test
    void ifAckIsDelayedThenDelayFieldIsOnlySetForFirstAck() throws Exception {
        // Given
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));

        // When
        clock.fastForward(10);

        // Then
        AckFrame firstAckFrame = ackGenerator.generateAckForPacket(13).get();
        AckFrame secondAckFrame = ackGenerator.generateAckForPacket(14).get();
        assertThat(secondAckFrame.getAckDelay()).isEqualTo(0);
    }

    @Test
    void ifAcksAreDelayedThenAckDelayShouldBeBasedOnOldestAck() throws Exception {
        // Given
        ackGenerator.packetReceived(new MockPacket(1, 83, EncryptionLevel.Initial));

        // When
        clock.fastForward(10);
        ackGenerator.packetReceived(new MockPacket(2, 83, EncryptionLevel.Initial));
        clock.fastForward(10);

        // Then
        Optional<AckFrame> ack = ackGenerator.generateAckForPacket(13);
        assertThat(ack.get().getAckDelay())
                .isGreaterThanOrEqualTo(20)
                .isLessThanOrEqualTo(25);
    }

    @Test
    void oneRttAcksAreGeneratedForEverySecondPacket() {
        // Given
        ackGenerator.packetReceived(new MockPacket(1, 83, EncryptionLevel.App));

        // Then
        verify(sender, times(1)).sendAck(PnSpace.App, 20);
        clearInvocations(sender);

        // And When
        ackGenerator.packetReceived(new MockPacket(2, 83, EncryptionLevel.App));
        // Then
        verify(sender, timeout(1)).sendAck(PnSpace.App, 0);
    }

    @Test
    void removeOneExactlyMatchingAcknowlegdedRange() {
        // Given
        ArrayList<Range> ackedRanges = new ArrayList<>(List.of(range(15, 19), range(7, 10), range(1, 4)));
        AckFrame ackFrame = new AckFrame(range(7, 10));

        // When
        ackGenerator.removeAcknowlegdedRanges(ackedRanges, ackFrame);

        // Then
        assertThat(ackedRanges).containsExactly(range(15, 19), range(1, 4));
    }

    @Test
    void removeMultipleExactlyMatchingAcknowlegdedRanges() {
        // Given
        ArrayList<Range> ackedRanges = new ArrayList<>(List.of(range(27, 36), range(25, 25), range(15, 19), range(7, 10), range(1, 4)));
        AckFrame ackFrame = new AckFrame(List.of(range(25, 25), range(15, 19)));

        // When
        ackGenerator.removeAcknowlegdedRanges(ackedRanges, ackFrame);

        // Then
        assertThat(ackedRanges).containsExactly(range(27, 36), range(7, 10), range(1, 4));
    }

    @Test
    void doNotRemoteNotMatchingAcknowlegdedRange() {
        // Given
        ArrayList<Range> ackedRanges = new ArrayList<>(List.of(range(25, 29), range(15, 19), range(7, 10), range(1, 4)));
        // Overlapping
        AckFrame ackFrame = new AckFrame(List.of(range(21, 23), range(15, 19)));

        // When
        ackGenerator.removeAcknowlegdedRanges(ackedRanges, ackFrame);

        // Then
        assertThat(ackedRanges).containsExactly(range(25, 29), range(7, 10), range(1, 4));
    }

    @Test
    void removeOnePartlyMatchingAcknowlegdedRange1() {
        // Given
        ArrayList<Range> ackedRanges = new ArrayList<>(List.of(range(15, 19), range(7, 10), range(1, 4)));
        // Overlapping
        AckFrame ackFrame = new AckFrame(range(7, 11));

        // When
        ackGenerator.removeAcknowlegdedRanges(ackedRanges, ackFrame);

        // Then
        assertThat(ackedRanges).containsExactly(range(15, 19), range(1, 4));
    }

    @Test
    void removeOnePartlyMatchingAcknowlegdedRange2() {
        // Given
        ArrayList<Range> ackedRanges = new ArrayList<>(List.of(range(15, 19), range(7, 10), range(1, 4)));
        // Overlapping
        AckFrame ackFrame = new AckFrame(range(7, 9));

        // When
        ackGenerator.removeAcknowlegdedRanges(ackedRanges, ackFrame);

        // Then
        assertThat(ackedRanges).containsExactly(range(15, 19), range(10), range(1, 4));
    }

    @Test
    void removeOnePartlyMatchingAcknowlegdedRange3() {
        // Given
        ArrayList<Range> ackedRanges = new ArrayList<>(List.of(range(15, 19), range(7, 10), range(1, 4)));
        // Overlapping
        AckFrame ackFrame = new AckFrame(range(6, 9));

        // When
        ackGenerator.removeAcknowlegdedRanges(ackedRanges, ackFrame);

        // Then
        assertThat(ackedRanges).containsExactly(range(15, 19), range(10), range(1, 4));
    }

    @Test
    void removeOnePartlyMatchingAcknowlegdedRange4() {
        // Given
        ArrayList<Range> ackedRanges = new ArrayList<>(List.of(range(15, 19), range(7, 10), range(1, 4)));
        // Overlapping
        AckFrame ackFrame = new AckFrame(range(5, 10));

        // When
        ackGenerator.removeAcknowlegdedRanges(ackedRanges, ackFrame);

        // Then
        assertThat(ackedRanges).containsExactly(range(15, 19), range(1, 4));
    }

    @Test
    void removeOnePartlyMatchingAcknowlegdedRange5() {
        // Given
        ArrayList<Range> ackedRanges = new ArrayList<>(List.of(range(15, 19), range(7, 10), range(1, 4)));
        // Overlapping
        AckFrame ackFrame = new AckFrame(range(2, 6));

        // When
        ackGenerator.removeAcknowlegdedRanges(ackedRanges, ackFrame);

        // Then
        assertThat(ackedRanges).containsExactly(range(15, 19), range(7, 10), range(1));
    }

    //region needs an ack
    @Test
    void shouldWantAckWhenTimeSinceLastCleanupWasLongEnoughInThePast() {
        // Given
        ackGenerator.packetReceived(new MockPacket(5, 83, EncryptionLevel.App));
        ackGenerator.generateAckForPacket(1);

        when(rttProvider.getSmoothedRtt()).thenReturn(20);
        Instant start = clock.instant();
        when(sender.lastAckElicitingSent()).thenReturn(start);
        clock.fastForward(100);

        // When
        ackGenerator.process(new AckFrame(1));
        clock.fastForward(21);

        // Then
        assertThat(ackGenerator.wantsAckFromPeer()).isTrue();
    }

    @Test
    void whenTimeSinceLastCleanupSmallerThenRtt() {
        // Given
        ackGenerator.packetReceived(new MockPacket(5, 83, EncryptionLevel.App));
        ackGenerator.generateAckForPacket(1);

        when(rttProvider.getSmoothedRtt()).thenReturn(20);
        Instant start = clock.instant();
        when(sender.lastAckElicitingSent()).thenReturn(start);
        clock.fastForward(100);

        // When
        ackGenerator.process(new AckFrame(1));
        clock.fastForward(19);

        // Then
        assertThat(ackGenerator.wantsAckFromPeer()).isFalse();
    }

    @Test
    void whenTimeSinceLastCleanupGreaterThenTinyRttButLessThenMinDuration() {
        // Given
        ackGenerator.packetReceived(new MockPacket(5, 83, EncryptionLevel.App));
        ackGenerator.generateAckForPacket(1);

        when(rttProvider.getSmoothedRtt()).thenReturn(3);
        Instant start = clock.instant();
        when(sender.lastAckElicitingSent()).thenReturn(start);
        clock.fastForward(100);

        // When
        ackGenerator.process(new AckFrame(1));
        clock.fastForward(9);

        // Then
        assertThat(ackGenerator.wantsAckFromPeer()).isFalse();
    }

    @Test
    void shouldWantAckWhenLastAckElicitingSentOlderThanThreshold() {
        // Given
        ackGenerator.packetReceived(new MockPacket(5, 83, EncryptionLevel.App));
        ackGenerator.generateAckForPacket(1);

        when(rttProvider.getSmoothedRtt()).thenReturn(20);
        Instant start = clock.instant();
        when(sender.lastAckElicitingSent()).thenReturn(start);

        ackGenerator.process(new AckFrame(1));

        // When
        clock.fastForward(31);

        // Then
        assertThat(ackGenerator.wantsAckFromPeer()).isTrue();
    }

    @Test
    void wantsAckReturnsFalseWhenLastAckElicitingSentTooRecent() {
        // Given
        ackGenerator.packetReceived(new MockPacket(5, 83, EncryptionLevel.App));
        ackGenerator.generateAckForPacket(1);

        when(rttProvider.getSmoothedRtt()).thenReturn(20);
        Instant start = clock.instant();
        when(sender.lastAckElicitingSent()).thenReturn(start);

        ackGenerator.process(new AckFrame(1));

        clock.fastForward(30);

        // Then
        assertThat(ackGenerator.wantsAckFromPeer()).isFalse();
    }
    //endregion

    //region helpers
    private Range range(int from, int to) {
        return new Range(from, to);
    }

    private Range range(int single) {
        return new Range(single, single);
    }
    //endregion
}