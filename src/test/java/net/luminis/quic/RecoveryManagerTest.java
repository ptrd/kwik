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

import java.time.Instant;

import static org.mockito.Mockito.*;

class RecoveryManagerTest extends RecoveryTests {

    private RecoveryManager recoveryManager;
    private LostPacketHandler lostPacketHandler;
    private int defaultRtt = 40;

    @BeforeEach
    void initObjectUnderTest() {
        RttEstimator rttEstimator = mock(RttEstimator.class);
        when(rttEstimator.getSmoothedRtt()).thenReturn(defaultRtt);
        when(rttEstimator.getLatestRtt()).thenReturn(defaultRtt);
        recoveryManager = new RecoveryManager(rttEstimator, mock(Logger.class));
    }

    @BeforeEach
    void initLostPacketCallback() {
        lostPacketHandler = mock(LostPacketHandler.class);
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


}
