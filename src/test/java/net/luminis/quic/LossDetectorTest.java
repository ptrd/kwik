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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;


class LossDetectorTest {

    private LossDetector lossDetector;
    private LostPacketHandler lostPacketHandler;
    private int defaultRtt = 10;

    @BeforeEach
    void initObjectUnderTest() {
        RttEstimator rttEstimator = mock(RttEstimator.class);
        when(rttEstimator.getSmoothedRtt()).thenReturn(defaultRtt);
        when(rttEstimator.getLatestRtt()).thenReturn(defaultRtt);
        lossDetector = new LossDetector(rttEstimator);
    }

    @BeforeEach
    void initLostPacketCallback() {
        lostPacketHandler = mock(LostPacketHandler.class);
    }

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

        lossDetector.onAckReceived(new AckFrame(List.of(1L, 2L)));

        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
    }

    @Test
    void packetIsLostWhenThreeLaterPacketsAreAcked() {
        List<QuicPacket> packets = createPackets(1, 2, 3, 4);
        lossDetector.packetSent(packets.get(0), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(packets.get(1), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(packets.get(2), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(packets.get(3), Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(List.of(2L, 3L, 4L)));

        verify(lostPacketHandler, times(1)).process(argThat(new PacketMatcher(1)));
    }

    @Test
    void ackOnlyPacketCannotBeDeclaredLost() {
        QuicPacket ackOnlyPacket = createPacket(1, new AckFrame());
        lossDetector.packetSent(ackOnlyPacket, Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket));

        List<QuicPacket> packets = createPackets(2, 3, 4);
        packets.forEach(p ->
                lossDetector.packetSent(p, Instant.now(), lostPacket -> lostPacketHandler.process(lostPacket)));

        lossDetector.onAckReceived(new AckFrame(List.of(2L, 3L, 4L)));

        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
    }

    @Test
    void packetTooOldIsDeclaredLost() {
        Instant now = Instant.now();
        int timeDiff = (defaultRtt * 9 / 8) + 1;
        lossDetector.packetSent(createPacket(6), now.minusMillis(timeDiff), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(8), now, lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(List.of(8L)));

        verify(lostPacketHandler, times(1)).process(argThat(new PacketMatcher(6)));
    }

    @Test
    void packetNotTooOldIsNotDeclaredLost() {
        Instant now = Instant.now();
        int timeDiff = defaultRtt - 1;  // Give some time for processing.
        lossDetector.packetSent(createPacket(6), now.minusMillis(timeDiff), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(8), now, lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(List.of(8L)));

        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
    }

    @Test
    void oldPacketLaterThanLargestAcknowledgedIsNotDeclaredLost() {
        Instant now = Instant.now();
        int timeDiff = (defaultRtt * 9 / 8) + 10;
        lossDetector.packetSent(createPacket(1), now.minusMillis(timeDiff), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(3), now.minusMillis(timeDiff), lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(List.of(1L)));

        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
    }

    @Test
    void packetNotYetLostIsLostAfterLostTime() throws InterruptedException {
        Instant now = Instant.now();
        int timeDiff = defaultRtt - 1;  // Give some time for processing.
        lossDetector.packetSent(createPacket(6), now.minusMillis(timeDiff), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(8), now, lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(List.of(8L)));

        verify(lostPacketHandler, never()).process(any(QuicPacket.class));
        assertThat(lossDetector.getLossTime()).isNotNull();

        Thread.sleep(Duration.between(lossDetector.getLossTime(), Instant.now()).toMillis());
        lossDetector.detectLostPackets();

        verify(lostPacketHandler, times(1)).process(argThat(new PacketMatcher(6)));
    }

    @Test
    void ifAllPacketsAreLostThenLostTimeIsNotSet() {
        Instant now = Instant.now();
        int timeDiff = (defaultRtt * 9 / 8) + 1;
        lossDetector.packetSent(createPacket(1), now.minusMillis(timeDiff), lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(5), now, lostPacket -> lostPacketHandler.process(lostPacket));
        lossDetector.packetSent(createPacket(8), now, lostPacket -> lostPacketHandler.process(lostPacket));

        lossDetector.onAckReceived(new AckFrame(List.of(8L)));

        assertThat(lossDetector.getLossTime()).isNull();
    }


    private QuicPacket createPacket(int packetNumber, QuicFrame frame) {
        ShortHeaderPacket packet = new ShortHeaderPacket(Version.getDefault(), new byte[0], frame);
        packet.packetNumber = packetNumber;
        return packet;
    }

    private QuicPacket createPacket(int packetNumber) {
        return createPacket(packetNumber, new Padding(1));
    }

    private List<QuicPacket>  createPackets(int... packetNumbers) {
        List<QuicPacket> packets = new ArrayList<>();
        for (int packetNumber: packetNumbers) {
            ShortHeaderPacket packet = new ShortHeaderPacket(Version.getDefault(), new byte[0], new Padding(1));
            packet.packetNumber = packetNumber;
            packets.add(packet);
        }
        return packets;
    }

    interface LostPacketHandler {
        void process(QuicPacket lostPacket);
    }


    static class PacketMatcher implements ArgumentMatcher<QuicPacket> {
        private int packetNumber;

        PacketMatcher(int packetNumber) {
            this.packetNumber = packetNumber;
        }

        @Override
        public boolean matches(QuicPacket quicPacket) {
            return quicPacket.getPacketNumber() == packetNumber;
        }
    }
}
