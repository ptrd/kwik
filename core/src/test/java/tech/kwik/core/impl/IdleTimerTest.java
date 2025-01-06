/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.impl;

import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.ShortHeaderPacket;
import tech.kwik.core.test.FieldSetter;
import tech.kwik.core.test.TestClock;
import tech.kwik.core.test.TestScheduledExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.concurrent.ScheduledExecutorService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class IdleTimerTest {

    private QuicConnectionImpl connection;
    private IdleTimer idleTimer;
    private TestClock clock;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        clock = new TestClock();
        connection = Mockito.mock(QuicConnectionImpl.class);
        idleTimer = new IdleTimer(clock, connection, mock(Logger.class), 1);
        ScheduledExecutorService scheduler = new TestScheduledExecutor(clock);
        FieldSetter.setField(idleTimer, idleTimer.getClass().getDeclaredField("timer"), scheduler);
    }

    @AfterEach
    void destroyTimer() {
        idleTimer.shutdown();
    }

    @Test
    void idleTimerShouldBeRestartedWhenPacketProcessed() throws Exception {
        idleTimer.setIdleTimeout(200);

        clock.fastForward(150);
        idleTimer.packetProcessed();

        clock.fastForward(150);
        verify(connection, never()).silentlyCloseConnection(anyInt());

        clock.fastForward(51);
        verify(connection, times(1)).silentlyCloseConnection(anyLong());
    }

    @Test
    void idleTimerShouldBeRestartedWhenPacketSent() throws Exception {
        idleTimer.setIdleTimeout(200);

        clock.fastForward(150);
        idleTimer.packetSent(new ShortHeaderPacket(Version.getDefault(), new byte[0], new PingFrame()), clock.instant());

        clock.fastForward(150);
        verify(connection, never()).silentlyCloseConnection(anyLong());

        clock.fastForward(51);
        verify(connection, times(1)).silentlyCloseConnection(anyLong());
    }

    @Test
    void ifThreeTimesPtoIsLargerThanIdleTimeoutConnectionShouldNotTimeoutBeforeThreeTimesPto() throws Exception {
        idleTimer.setIdleTimeout(200);
        idleTimer.setPtoSupplier(() -> 100);

        clock.fastForward(201);
        verify(connection, never()).silentlyCloseConnection(anyLong());

        clock.fastForward(100);
        verify(connection, times(1)).silentlyCloseConnection(anyLong());
    }

    @Test
    void whenLastActionWasPacketReceivedItIsNotTailLoss() {
        // Given
        idleTimer.setIdleTimeout(200);
        clock.fastForward(150);
        idleTimer.packetProcessed();
        clock.fastForward(50);

        // Then
        assertThat(idleTimer.isTailLoss()).isFalse();
    }

    @Test
    void whenLastActionWasPacketSentItIsTailLoss() {
        // Given
        idleTimer.setIdleTimeout(200);
        clock.fastForward(150);
        idleTimer.packetSent(new ShortHeaderPacket(Version.getDefault(), new byte[0], new PingFrame()), clock.instant());
        clock.fastForward(50);

        // Then
        assertThat(idleTimer.isTailLoss()).isTrue();
    }

    @Test
    void whenSendingAckElicitingItShouldNotResetTimerWhenNotTheFirst() {
        // Given
        idleTimer.setIdleTimeout(200);
        clock.fastForward(150);
        idleTimer.packetSent(new ShortHeaderPacket(Version.getDefault(), new byte[0], new PingFrame()), clock.instant());
        clock.fastForward(150);

        // When
        idleTimer.packetSent(new ShortHeaderPacket(Version.getDefault(), new byte[0], new PingFrame()), clock.instant());
        clock.fastForward(150);

        // Then
        verify(connection).silentlyCloseConnection(anyLong());
    }

}