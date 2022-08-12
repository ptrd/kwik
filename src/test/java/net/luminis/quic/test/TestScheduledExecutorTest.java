/*
 * Copyright © 2022 Peter Doornbosch
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
package net.luminis.quic.test;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

public class TestScheduledExecutorTest {

    private TestClock clock;
    private TestScheduledExecutor scheduledExecutor;

    @BeforeEach
    void initObjectUnderTest() {
        clock = new TestClock();
        scheduledExecutor = new TestScheduledExecutor(clock);
    }

    @Test
    void taskShouldNotBeRunWhileScheduledTimeHasNotYetArrived() {
        AtomicBoolean hasBeenExecuted = new AtomicBoolean(false);
        scheduledExecutor.schedule(() -> hasBeenExecuted.set(true), 300, TimeUnit.MILLISECONDS);
        clock.fastForward(100);

        assertThat(hasBeenExecuted.get()).isFalse();
    }

    @Test
    void taskShouldHaveBeenRunWhenScheduledTimeHasPassed() {
        AtomicBoolean hasBeenExecuted = new AtomicBoolean(false);
        scheduledExecutor.schedule(() -> hasBeenExecuted.set(true), 300, TimeUnit.MILLISECONDS);
        clock.fastForward(400);

        assertThat(hasBeenExecuted.get()).isTrue();
    }

    @Test
    void taskShouldHaveBeenRunWhenScheduledTimeHasCome() {
        AtomicBoolean hasBeenExecuted = new AtomicBoolean(false);
        scheduledExecutor.schedule(() -> hasBeenExecuted.set(true), 300, TimeUnit.MILLISECONDS);
        clock.fastForward(300);

        assertThat(hasBeenExecuted.get()).isTrue();
    }

    @Test
    void whenTaskIsCancelledBeforeItsRunItWillNotRun() {
        AtomicBoolean hasBeenExecuted = new AtomicBoolean(false);
        ScheduledFuture<?> scheduledFuture = scheduledExecutor.schedule(() -> hasBeenExecuted.set(true), 300, TimeUnit.MILLISECONDS);
        clock.fastForward(200);
        scheduledFuture.cancel(true);
        clock.fastForward(200);

        assertThat(hasBeenExecuted.get()).isFalse();
    }

    @Test
    void scheduledAtFixedRateShouldRunAfterInitialDelay() {
        AtomicInteger hasBeenExecuted = new AtomicInteger(0);
        scheduledExecutor.scheduleAtFixedRate(() -> hasBeenExecuted.incrementAndGet(), 100, 300, TimeUnit.MILLISECONDS);
        clock.fastForward(100);

        assertThat(hasBeenExecuted.get()).isEqualTo(1);
    }

    @Test
    void scheduledAtFixedRateShouldRunRepeatedly() {
        AtomicInteger hasBeenExecuted = new AtomicInteger(0);
        scheduledExecutor.scheduleAtFixedRate(() -> hasBeenExecuted.incrementAndGet(), 100, 300, TimeUnit.MILLISECONDS);
        clock.fastForward(100);
        clock.fastForward(300);
        clock.fastForward(300);

        assertThat(hasBeenExecuted.get()).isEqualTo(3);
    }

    @Test
    void scheduledAtFixedRateShouldHaveBeenRunRepeatedly() {
        AtomicInteger hasBeenExecuted = new AtomicInteger(0);
        scheduledExecutor.scheduleAtFixedRate(() -> hasBeenExecuted.incrementAndGet(), 100, 400, TimeUnit.MILLISECONDS);
        clock.fastForward(1000);

        assertThat(hasBeenExecuted.get()).isEqualTo(3);
    }

    @Test
    void scheduledAtFixedRateShouldRunNoMoreWhenShutdown() {
        AtomicInteger hasBeenExecuted = new AtomicInteger(0);
        scheduledExecutor.scheduleAtFixedRate(() -> {
            hasBeenExecuted.incrementAndGet();
            scheduledExecutor.shutdown();
        }, 100, 300, TimeUnit.MILLISECONDS);
        clock.fastForward(1200);

        assertThat(hasBeenExecuted.get()).isEqualTo(1);
    }

    @Test
    void whenShutdownTasksWillNotBeRun() {
        AtomicBoolean hasBeenExecuted = new AtomicBoolean(false);
        scheduledExecutor.schedule(() -> hasBeenExecuted.set(true), 100, TimeUnit.MILLISECONDS);
        scheduledExecutor.shutdown();
        clock.fastForward(500);

        assertThat(hasBeenExecuted.get()).isFalse();
    }

    @Test
    void whenShutdownNowTasksWillNotBeRun() {
        AtomicBoolean hasBeenExecuted = new AtomicBoolean(false);
        scheduledExecutor.schedule(() -> hasBeenExecuted.set(true), 100, TimeUnit.MILLISECONDS);
        scheduledExecutor.shutdownNow();
        clock.fastForward(500);

        assertThat(hasBeenExecuted.get()).isFalse();
    }
}
