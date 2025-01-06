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

import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.impl.MockPacket;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.packet.PacketInfo;
import tech.kwik.core.packet.QuicPacket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class NewRenoCongestionControllerTest {

    private CongestionController congestionController;

    // Arbitrary Instant value, used by tests to indicate the value does not matter for the test
    private Instant whenever = Instant.now();

    @BeforeEach
    void initObjectUnderTest() {
        congestionController = new NewRenoCongestionController(new NullLogger(), mock(CongestionControlEventListener.class));
    }

    @Test
    void initialValueForCwnd() {
        assertThat(congestionController.getWindowSize()).isEqualTo(12_000);
    }

    @Test
    void initiallyModeIsSlowStart() {
        assertThat(((NewRenoCongestionController) congestionController).getMode()).isEqualTo(NewRenoCongestionController.Mode.SlowStart);
    }

    @Test
    void whenInSlowStartCwndIsNotIncreasesWhenUnderUtilized() {
        long initialCwnd = congestionController.getWindowSize();
        QuicPacket packet = new MockPacket(new Padding(800));
        congestionController.registerInFlight(packet);
        congestionController.registerAcked(List.of(new PacketInfo(whenever, packet, this::noOp)));

        assertThat(congestionController.getWindowSize()).isEqualTo(initialCwnd);
    }

    @Test
    void whenInSlowStartCwndIncreasesByNumberOfBytesAcked() {
        // Given (cwnd is fully utilized)
        long initialCwnd = congestionController.getWindowSize();
        QuicPacket hugePacket = new MockPacket(new Padding((int) initialCwnd));
        congestionController.registerInFlight(hugePacket);

        // When
        MockPacket normalPacket = new MockPacket(new Padding(1100));
        congestionController.registerInFlight(normalPacket);
        congestionController.registerAcked(List.of(new PacketInfo(whenever, normalPacket, this::noOp)));

        assertThat(congestionController.getWindowSize()).isEqualTo(initialCwnd + normalPacket.getSize());
    }

    @Test
    void modeIsSlowStartUntilPacketLost() {
        QuicPacket packet = new MockPacket(new Padding(800));

        congestionController.registerInFlight(packet);
        congestionController.registerInFlight(packet);
        congestionController.registerAcked(List.of(new PacketInfo(whenever, packet, this::noOp)));
        congestionController.registerInFlight(packet);
        congestionController.registerInFlight(packet);
        congestionController.registerInFlight(packet);
        congestionController.registerAcked(List.of(new PacketInfo(whenever, packet, this::noOp)));
        congestionController.registerAcked(List.of(new PacketInfo(whenever, packet, this::noOp)));
        congestionController.registerAcked(List.of(new PacketInfo(whenever, packet, this::noOp)));
        assertThat(((NewRenoCongestionController) congestionController).getMode()).isEqualTo(NewRenoCongestionController.Mode.SlowStart);

        congestionController.registerLost(List.of(new PacketInfo(whenever, packet, this::noOp)));
        assertThat(((NewRenoCongestionController) congestionController).getMode()).isNotEqualTo(NewRenoCongestionController.Mode.SlowStart);
    }

    @Test
    void whenPacketLostCongestionWindowHalves() {
        long initialCwnd = congestionController.getWindowSize();
        QuicPacket packet = new MockPacket(new Padding(800));
        congestionController.registerInFlight(packet);
        congestionController.registerLost(List.of(new PacketInfo(whenever, packet, this::noOp)));

        assertThat(congestionController.getWindowSize()).isEqualTo(initialCwnd / 2);
    }

    @Test
    void lossOfPacketSentBeforeCongestionRecoveryDoesNotChangeCongestionWindow() {
        long initialCwnd = congestionController.getWindowSize();
        QuicPacket packet1 = new MockPacket(new Padding(800));
        Instant timeFirstPacketSent = Instant.now();
        congestionController.registerInFlight(packet1);

        QuicPacket packet2 = new MockPacket(new Padding(800));
        Instant timeSecondPacketSent = timeFirstPacketSent.plusMillis(1);
        congestionController.registerInFlight(packet2);

        congestionController.registerLost(List.of(new PacketInfo(timeSecondPacketSent, packet2, this::noOp)));
        // As tested before (whenPacketLostCongestionWindowHalves)
        assertThat(congestionController.getWindowSize()).isEqualTo(initialCwnd / 2);

        congestionController.registerLost(List.of(new PacketInfo(timeFirstPacketSent, packet1, this::noOp)));
        assertThat(congestionController.getWindowSize()).isEqualTo(initialCwnd / 2);
    }

    @Test
    void lossOfPacketSentAfterCongestionRecoveryChangesCongestionWindowAgain() {
        Instant startOfRecovery = Instant.now();  // More or less...

        long initialCwnd = congestionController.getWindowSize();
        QuicPacket packet1 = new MockPacket(new Padding(800));
        Instant timeFirstPacketSent = startOfRecovery.minusMillis(2);
        congestionController.registerInFlight(packet1);

        QuicPacket packet2 = new MockPacket(new Padding(800));
        congestionController.registerInFlight(packet2);

        congestionController.registerLost(List.of(new PacketInfo(timeFirstPacketSent, packet1, this::noOp)));
        // Recovery is just started, so now we can set the proper sent time of second packet:
        Instant timeSecondPacketSent = Instant.now().plusMillis(1);

        // As tested before (whenPacketLostCongestionWindowHalves)
        assertThat(congestionController.getWindowSize()).isEqualTo(initialCwnd / 2);

        congestionController.registerLost(List.of(new PacketInfo(timeSecondPacketSent, packet2, this::noOp)));
        assertThat(congestionController.getWindowSize()).isEqualTo(initialCwnd / 2 / 2);
    }

    @Test
    void acknowledgeOfPacketSentBeforeCongestionRecoveryDoesNotChangeCongestionWindow() {
        long initialCwnd = congestionController.getWindowSize();
        QuicPacket packet1 = new MockPacket(new Padding(800));
        Instant timeFirstPacketSent = Instant.now();
        congestionController.registerInFlight(packet1);

        QuicPacket packet2 = new MockPacket(new Padding(800));
        Instant timeSecondPacketSent = timeFirstPacketSent.plusMillis(1);
        congestionController.registerInFlight(packet2);

        congestionController.registerLost(List.of(new PacketInfo(timeSecondPacketSent, packet2, this::noOp)));
        // As tested before (whenPacketLostCongestionWindowHalves)
        assertThat(congestionController.getWindowSize()).isEqualTo(initialCwnd / 2);

        congestionController.registerAcked(List.of(new PacketInfo(timeFirstPacketSent, packet1, this::noOp)));
        assertThat(congestionController.getWindowSize()).isEqualTo(initialCwnd / 2);
    }

    @Test
    void acknowledgeOfPacketSentAfterCongestionRecoveryChangesCongestionWindow() {
        Instant startOfRecovery = Instant.now();  // More or less..

        long initialCwnd = congestionController.getWindowSize();
        QuicPacket packet1 = new MockPacket(new Padding(800));
        Instant timeFirstPacketSent = startOfRecovery.minusMillis(2);
        congestionController.registerInFlight(packet1);

        QuicPacket packet2 = new MockPacket(new Padding(6000));
        congestionController.registerInFlight(packet2);

        congestionController.registerLost(List.of(new PacketInfo(timeFirstPacketSent, packet1, this::noOp)));
        // Recovery is just started, so now we can set the proper sent time of second packet:
        Instant timeSecondPacketSent = Instant.now().plusMillis(1);

        // As tested before (whenPacketLostCongestionWindowHalves)
        assertThat(congestionController.getWindowSize()).isEqualTo(initialCwnd / 2);

        congestionController.registerAcked(List.of(new PacketInfo(timeSecondPacketSent, packet2, this::noOp)));
        assertThat(congestionController.getWindowSize()).isGreaterThan(initialCwnd / 2);
    }

    @Test
    void congestionWindowNeverDropsBelowMinimumWindowSize() {
        QuicPacket packet = new MockPacket(new Padding(1000));
        for (int i = 0; i < 10; i++) {
            congestionController.registerLost(List.of(new PacketInfo(Instant.now(), packet, this::noOp)));
        }

        assertThat(congestionController.getWindowSize()).isGreaterThanOrEqualTo(2400);
    }

    @Test
    void congestionAvoidance() {
        long initialCwnd = congestionController.getWindowSize();
        assertThat(initialCwnd).isEqualTo(12000);

        QuicPacket packet = new MockPacket(new Padding(800));
        congestionController.registerInFlight(packet);
        congestionController.registerLost(List.of(new PacketInfo(whenever, packet, this::noOp)));

        // As tested before (whenPacketLostCongestionWindowHalves)
        assertThat(congestionController.getWindowSize()).isEqualTo(6000);

        assertThat(((NewRenoCongestionController) congestionController).getMode()).isEqualTo(NewRenoCongestionController.Mode.CongestionAvoidance);

        MockPacket newPacket = new MockPacket(0, 6000, EncryptionLevel.App);
        congestionController.registerInFlight(newPacket);
        congestionController.registerAcked(List.of(new PacketInfo(Instant.now(), newPacket, this::noOp)));
        // cwnd was 6000; congestion avoidance adds 1200 * 6000 / 6000 = 1200
        assertThat(congestionController.getWindowSize()).isEqualTo(7200);
    }

    @Test
    void onceInCongestionAvoidanceModeItNeverLeavesThatMode() {
        QuicPacket packet = new MockPacket(new Padding(800));
        congestionController.registerInFlight(packet);
        congestionController.registerLost(List.of(new PacketInfo(whenever, packet, this::noOp)));

        assertThat(((NewRenoCongestionController) congestionController).getMode()).isEqualTo(NewRenoCongestionController.Mode.CongestionAvoidance);

        congestionController.registerInFlight(packet);
        congestionController.registerInFlight(packet);
        congestionController.registerLost(List.of(new PacketInfo(Instant.now(), packet, this::noOp)));
        congestionController.registerInFlight(packet);
        congestionController.registerLost(List.of(new PacketInfo(Instant.now(), packet, this::noOp)));
        congestionController.registerLost(List.of(new PacketInfo(Instant.now(), packet, this::noOp)));

        assertThat(((NewRenoCongestionController) congestionController).getMode()).isEqualTo(NewRenoCongestionController.Mode.CongestionAvoidance);
    }

    private void noOp(QuicPacket packet) {}
}
