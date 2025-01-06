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
package tech.kwik.core.cc;

import tech.kwik.core.impl.MockPacket;
import tech.kwik.core.frame.AckFrame;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketInfo;
import tech.kwik.core.packet.QuicPacket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;


/**
 * Any implementation of CongestionController should pass these tests.
 */
class CongestionControllerTest {

    private CongestionController congestionController;

    // Arbitrary Instant value, used by tests to indicate the value does not matter for the test
    private Instant whenever = Instant.now();

    @BeforeEach
    void initObjectUnderTest() {
        Logger logger = mock(Logger.class);
        // logger = new SysOutLogger();
        congestionController = new FixedWindowCongestionController(logger);
    }

    @Test
    void initialValueForCwnd() {
        assertThat(congestionController.getWindowSize()).isEqualTo(12_000);
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
    void packetWithAckFrameAmongstOthersDoesCountTowardCongestionControl() {
        long initiallyInFlight = congestionController.getBytesInFlight();
        congestionController.registerInFlight(new MockPacket(new Padding(100), new AckFrame(0)));

        assertThat(congestionController.getBytesInFlight()).isGreaterThan(initiallyInFlight + 100);
    }

    @Test
    void ackedPacketMustDecreaseBytesInFlight() {
        long initiallyInFlight = congestionController.getBytesInFlight();
        MockPacket packet = new MockPacket(new Padding(100), new AckFrame(0));
        congestionController.registerInFlight(packet);
        assertThat(congestionController.getBytesInFlight()).isGreaterThan(initiallyInFlight);

        congestionController.registerAcked(List.of(new PacketInfo(Instant.now(), packet, this::noOp)));

        assertThat(congestionController.getBytesInFlight()).isEqualTo(initiallyInFlight);
    }

    @Test
    void lostPacketMustDecreaseBytesInFlight() {
        long initiallyInFlight = congestionController.getBytesInFlight();
        MockPacket packet = new MockPacket(new Padding(100), new AckFrame(0));
        congestionController.registerInFlight(packet);
        assertThat(congestionController.getBytesInFlight()).isGreaterThan(initiallyInFlight);

        congestionController.registerLost(List.of(new PacketInfo(Instant.now(), packet, this::noOp)));

        assertThat(congestionController.getBytesInFlight()).isEqualTo(initiallyInFlight);
    }

    @Test
    void bytesInFlightCannotBecomeNegative() {
        MockPacket packet = new MockPacket(new Padding(100), new AckFrame(0));
        congestionController.registerAcked(List.of(new PacketInfo(Instant.now(), packet, this::noOp)));

        assertThat(congestionController.getBytesInFlight()).isGreaterThanOrEqualTo(0);
    }

    void noOp(QuicPacket packet) {}

}
