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
package net.luminis.quic;

import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.packet.RetryPacket;
import net.luminis.quic.packet.VersionNegotiationPacket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AckGeneratorTest {

    private AckGenerator ackGenerator;

    @BeforeEach
    void initObjectUnderTest() {
        ackGenerator = new AckGenerator();
    }

    @Test
    void newGeneratorDoesNotGenerateAck() {
        assertThat(ackGenerator.hasAckToSend()).isEqualTo(false);
    }

    @Test
    void receivingPacketLeadsToSingleAck() {
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));
        assertThat(ackGenerator.hasAckToSend()).isEqualTo(true);

        AckFrame ack = ackGenerator.generateAckForPacket(0);

        assertThat(ack.getLargestAcknowledged()).isEqualTo(0);
        assertThat(ack.getAckedPacketNumbers()).containsOnly(0L);
    }

    @Test
    void receivingMultipleConsequetivePacketLeadsToRangeAck() {
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(1, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(2, 83, EncryptionLevel.Initial));

        assertThat(ackGenerator.hasAckToSend()).isEqualTo(true);

        AckFrame ack = ackGenerator.generateAckForPacket(0);

        assertThat(ack.getLargestAcknowledged()).isEqualTo(2);
        assertThat(ack.getAckedPacketNumbers()).containsOnly(0L, 1L, 2L);
    }

    @Test
    void afterReceivingMorePacketsOldAcksRemain() {
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(1, 83, EncryptionLevel.Initial));

        AckFrame ack1 = ackGenerator.generateAckForPacket(1);
        assertThat(ack1.getAckedPacketNumbers()).containsOnly(0L, 1L);

        ackGenerator.packetReceived(new MockPacket(3, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(5, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(6, 83, EncryptionLevel.Initial));

        AckFrame ack2 = ackGenerator.generateAckForPacket(1);

        assertThat(ack2.getLargestAcknowledged()).isEqualTo(6);
        assertThat(ack2.getAckedPacketNumbers()).containsOnly(0L, 1L, 3L, 5L, 6L);
    }

    @Test
    void afterProcessingReceivedAckForAllSentAcksThereAreNoAcksToSend() {
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(1, 83, EncryptionLevel.Initial));

        AckFrame ack1 = ackGenerator.generateAckForPacket(1);
        assertThat(ack1.getAckedPacketNumbers()).containsOnly(0L, 1L);

        ackGenerator.process(new AckFrame(1));

        assertThat(ackGenerator.hasAckToSend()).isEqualTo(false);
    }

    @Test
    void afterProcessingReceivedAckAcknowledgedAcksAreRemoved() {
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));
        ackGenerator.packetReceived(new MockPacket(1, 83, EncryptionLevel.Initial));

        AckFrame ack1 = ackGenerator.generateAckForPacket(6);
        assertThat(ack1.getAckedPacketNumbers()).containsOnly(0L, 1L);

        ackGenerator.process(new AckFrame(6));  // This acks the ack sent in packet 6 -> ack1
        ackGenerator.packetReceived(new MockPacket(2, 83, EncryptionLevel.Initial));

        assertThat(ackGenerator.hasAckToSend()).isEqualTo(true);

        AckFrame ack2 = ackGenerator.generateAckForPacket(2);
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

        AckFrame ack = ackGenerator.generateAckForPacket(0);

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
        Thread.sleep(10);

        // Then
        AckFrame ackFrame = ackGenerator.generateAckForPacket(13);
        assertThat(ackFrame.getAckDelay()).isGreaterThanOrEqualTo(10);
    }

    @Test
    void ifAckIsDelayedThenDelayFieldIsOnlySetForFirstAck() throws Exception {
        // Given
        ackGenerator.packetReceived(new MockPacket(0, 83, EncryptionLevel.Initial));

        // When
        Thread.sleep(10);

        // Then
        AckFrame firstAckFrame = ackGenerator.generateAckForPacket(13);
        AckFrame secondAckFrame = ackGenerator.generateAckForPacket(14);
        assertThat(secondAckFrame.getAckDelay()).isEqualTo(0);
    }
}
