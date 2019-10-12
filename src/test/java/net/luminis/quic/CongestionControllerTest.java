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
import org.mockito.Mock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.in;
import static org.mockito.Mockito.mock;


/**
 * Any implementation of CongestionController should pass these tests.
 */
class CongestionControllerTest {

    private CongestionController congestionController;

    @BeforeEach
    void initObjectUnderTest() {
        congestionController = new FixedWindowCongestionController(mock(Logger.class));
    }

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-23#section-3
    // "Packets that contain only ACK frames do not count toward
    //      congestion control limits"
    @Test
    void packetWithOnlyAckFramesDoesNotCountTowardCongestionControl() {
        long initiallyInFlight = congestionController.getBytesInFlight();
        congestionController.registerInFlight(new MockPacket(new AckFrame(0)));

        assertThat(congestionController.getBytesInFlight()).isEqualTo(initiallyInFlight);
    }

    @Test
    void packetWithOnlyAckFramesDoesNotCountTowardCongestionControlWhenAcked() {
        MockPacket ackOnlyPacket = new MockPacket(new AckFrame(0));
        congestionController.registerInFlight(ackOnlyPacket);
        congestionController.registerInFlight(new MockPacket(new Padding(100), new AckFrame(0)));

        long inFlight = congestionController.getBytesInFlight();
        congestionController.registerAcked(ackOnlyPacket);
        assertThat(congestionController.getBytesInFlight()).isEqualTo(inFlight);
    }

    @Test
    void packetWithAckFrameAmongstOthersDoesCountTowardCongestionControl() {
        long initiallyInFlight = congestionController.getBytesInFlight();
        congestionController.registerInFlight(new MockPacket(new Padding(100), new AckFrame(0)));

        assertThat(congestionController.getBytesInFlight()).isGreaterThan(initiallyInFlight + 100);
    }

    @Test
    void lostPacketMustDecreaseBytesInFlight() {
        long initiallyInFlight = congestionController.getBytesInFlight();
        MockPacket packet = new MockPacket(new Padding(100), new AckFrame(0));
        congestionController.registerInFlight(packet);
        assertThat(congestionController.getBytesInFlight()).isGreaterThan(initiallyInFlight);

        congestionController.registerLost(packet);

        assertThat(congestionController.getBytesInFlight()).isEqualTo(initiallyInFlight);
    }

    @Test
    void lostPacketWithOnlyAckFramesMustNotDecreaseBytesInFlight() {
        MockPacket ackOnlyPacket = new MockPacket(new AckFrame(0));
        congestionController.registerInFlight(ackOnlyPacket);
        long inFlight = congestionController.getBytesInFlight();

        congestionController.registerLost(ackOnlyPacket);

        assertThat(congestionController.getBytesInFlight()).isEqualTo(inFlight);
    }
}
