/*
 * Copyright © 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.test;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
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
    void submittedRunnableShouldRunImmediately() {
        AtomicInteger hasBeenExecuted = new AtomicInteger(0);
        scheduledExecutor.submit(() -> {
            hasBeenExecuted.incrementAndGet();
        });
        scheduledExecutor.check();

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

    @Test
    void whenTaskSchedulesNewTaskBothShouldHaveBeenRun() {
        AtomicInteger hasBeenExecuted = new AtomicInteger(0);
        scheduledExecutor.schedule(() -> {
            hasBeenExecuted.incrementAndGet();
            scheduledExecutor.schedule((Runnable) () -> hasBeenExecuted.incrementAndGet(), 100, TimeUnit.MILLISECONDS);
        }, 100, TimeUnit.MILLISECONDS);
        clock.fastForward(200);

        assertThat(hasBeenExecuted.get()).isEqualTo(2);
    }

    @Test
    void whenSecondTaskSchedulesNewTaskAllShouldHaveBeenRun() {
        AtomicInteger hasBeenExecuted = new AtomicInteger(0);
        scheduledExecutor.schedule(() -> {
            hasBeenExecuted.incrementAndGet();
        }, 100, TimeUnit.MILLISECONDS);
        scheduledExecutor.schedule(() -> {
            hasBeenExecuted.incrementAndGet();
            scheduledExecutor.schedule((Runnable) () -> hasBeenExecuted.incrementAndGet(), 10, TimeUnit.MILLISECONDS);
        }, 200, TimeUnit.MILLISECONDS);
        clock.fastForward(110);
        clock.fastForward(110);

        assertThat(hasBeenExecuted.get()).isEqualTo(3);
    }

    @Test
    void whenScheduledTooEarlyItIsExecutedInDueTime() {
        AtomicInteger hasBeenExecuted = new AtomicInteger(0);
        AtomicInteger hasBeenRescheduled = new AtomicInteger(0);
        Instant scheduledTime = clock.instant().plusMillis(10);
        scheduledExecutor.schedule(() -> doIt(hasBeenExecuted, scheduledTime, hasBeenRescheduled), 9, TimeUnit.MILLISECONDS);
        clock.fastForward(15);

        assertThat(hasBeenExecuted.get()).isEqualTo(1);
        assertThat(hasBeenRescheduled.get()).isLessThan(100_000);
    }

    private void doIt(AtomicInteger hasBeenExecuted, Instant scheduledTime, AtomicInteger hasBeenRescheduled) {
        if (clock.instant().isAfter(scheduledTime)) {
            Duration delay = Duration.between(scheduledTime, clock.instant());
            assertThat(delay.toMillis()).isLessThan(1);
            hasBeenExecuted.incrementAndGet();
        }
        else {
            Duration duration = Duration.between(clock.instant(), scheduledTime);
            long delay = duration.toMillis();
            hasBeenRescheduled.incrementAndGet();
            scheduledExecutor.schedule(() -> doIt(hasBeenExecuted, scheduledTime, hasBeenRescheduled), delay, TimeUnit.MILLISECONDS);
        }
    }
}
