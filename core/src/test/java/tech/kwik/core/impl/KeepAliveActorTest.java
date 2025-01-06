/*
 * Copyright © 2023, 2024, 2025 Peter Doornbosch
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

import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.send.Sender;
import tech.kwik.core.test.TestClock;
import tech.kwik.core.test.TestScheduledExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ScheduledExecutorService;

import static org.mockito.Mockito.*;

class KeepAliveActorTest {

    private TestClock clock;
    private KeepAliveActor keepAliveActor;
    private Sender sender;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        clock = new TestClock();
        sender = mock(Sender.class);
        ScheduledExecutorService scheduler = new TestScheduledExecutor(clock);
        keepAliveActor = new KeepAliveActor(clock, new VersionHolder(Version.getDefault()), 300, 30000, sender, scheduler);
    }

    @AfterEach
    void destroyTimer() {
        keepAliveActor.shutdown();
    }

    @Test
    void actorShouldSendPingBeforeIdle() {
        clock.fastForward(30000);
        verify(sender, atLeastOnce()).send(argThat(frame -> frame instanceof PingFrame), eq(EncryptionLevel.App));
    }

    @Test
    void actorShouldNotSendAnythingAfterShutdown() {
        clock.fastForward(35000);
        verify(sender, atLeastOnce()).send(argThat(frame -> frame instanceof PingFrame), eq(EncryptionLevel.App));

        clearInvocations(sender);
        keepAliveActor.shutdown();

        clock.fastForward(99000);
        verify(sender, never()).send(argThat(frame -> frame instanceof PingFrame), eq(EncryptionLevel.App));

    }

}