/*
 * Copyright © 2020 Peter Doornbosch
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

import net.luminis.quic.frame.PingFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.ShortHeaderPacket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.*;

class IdleTimerTest {

    private QuicConnectionImpl connection;
    private IdleTimer idleTimer;
    private int delta = 30;

    @BeforeEach
    void initObjectUnderTest() {
        connection = Mockito.spy(mock(QuicConnectionImpl.class));
        idleTimer = new IdleTimer(connection, () -> 50, mock(Logger.class), 10);
    }

    @AfterEach
    void destroyTimer() {
        idleTimer.shutdown();
    }

    @Test
    void idleTimerShouldBeRestartedWhenPacketProcessed() throws Exception {
        idleTimer.setIdleTimeout(200);

        Thread.sleep(150);
        idleTimer.packetProcessed();

        Thread.sleep(150);
        verify(connection, never()).silentlyCloseConnection(anyInt());

        Thread.sleep(50 + delta);
        verify(connection, times(1)).silentlyCloseConnection(anyLong());
    }

    @Test
    void idleTimerShouldBeRestartedWhenPacketSent() throws Exception {
        idleTimer.setIdleTimeout(200);

        Thread.sleep(150);
        idleTimer.packetSent(new ShortHeaderPacket(Version.getDefault(), new byte[0], new PingFrame()), Instant.now());

        Thread.sleep(150);
        verify(connection, never()).silentlyCloseConnection(anyLong());

        Thread.sleep(50 + delta);
        verify(connection, times(1)).silentlyCloseConnection(anyLong());
    }

    @Test
    void ifThreeTimesPtoIsLargerThanIdleTimeoutConnectionShouldNotTimeoutBeforeThreeTimesPto() throws Exception {
        idleTimer = new IdleTimer(connection, () -> 100, mock(Logger.class), 10);
        idleTimer.setIdleTimeout(200);

        Thread.sleep(200 + delta);
        verify(connection, never()).silentlyCloseConnection(anyLong());

        Thread.sleep(100);
        verify(connection, times(1)).silentlyCloseConnection(anyLong());
    }

}