/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.core.util;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class OneShotRateLimiterTest {

    @Test
    void firstInvocationForSubjectIsExecuted() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter();
        List<Integer> invocationNumbers = new ArrayList<>();

        rateLimiter.execute("subject", () -> invocationNumbers.add(0));

        assertThat(invocationNumbers).containsExactly(0);
    }

    @Test
    void secondInvocationForSameSubjectIsNotExecuted() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter();
        List<Integer> invocationNumbers = new ArrayList<>();

        rateLimiter.execute("subject", () -> invocationNumbers.add(0));
        rateLimiter.execute("subject", () -> invocationNumbers.add(1));

        assertThat(invocationNumbers).containsExactly(0);
    }

    @Test
    void repeatedInvocationsForSameSubjectAreNotExecuted() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter();
        List<Integer> invocationNumbers = new ArrayList<>();

        for (int i = 0; i < 100; i++) {
            int index = i;
            rateLimiter.execute("subject", () -> invocationNumbers.add(index));
        }

        assertThat(invocationNumbers).containsExactly(0);
    }

    @Test
    void eachSubjectIsExecutedOnce() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter();
        List<String> executed = new ArrayList<>();

        rateLimiter.execute("first", () -> executed.add("first"));
        rateLimiter.execute("second", () -> executed.add("second"));
        rateLimiter.execute("first", () -> executed.add("first again"));
        rateLimiter.execute("second", () -> executed.add("second again"));
        rateLimiter.execute("third", () -> executed.add("third"));

        assertThat(executed).containsExactly("first", "second", "third");
    }

    @Test
    void subjectsAreDistinguishedByEquality() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter();
        List<Integer> invocationNumbers = new ArrayList<>();

        Object subject1 = Integer.valueOf(444444444);
        rateLimiter.execute(subject1, () -> invocationNumbers.add(0));
        Object subject2 = Integer.valueOf(444444444);
        assertThat(subject1).isEqualTo(subject2);
        assertThat(subject1).isNotSameAs(subject2);
        rateLimiter.execute(subject2, () -> invocationNumbers.add(1));

        assertThat(invocationNumbers).containsExactly(0);
    }

    @Test
    void nullSubjectIsNotSupported() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter();
        List<Integer> invocationNumbers = new ArrayList<>();

        assertThatThrownBy(() -> rateLimiter.execute(null, () -> invocationNumbers.add(0)))
                .isInstanceOf(NullPointerException.class);

        assertThat(invocationNumbers).isEmpty();
    }

    @Test
    void afterResetSubjectIsExecutedAgain() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter();
        List<Integer> invocationNumbers = new ArrayList<>();
        rateLimiter.execute("subject", () -> invocationNumbers.add(0));
        rateLimiter.execute("subject", () -> invocationNumbers.add(1));

        rateLimiter.reset();

        rateLimiter.execute("subject", () -> invocationNumbers.add(2));
        rateLimiter.execute("subject", () -> invocationNumbers.add(3));

        assertThat(invocationNumbers).containsExactly(0, 2);
    }

    @Test
    void resetOnUnusedRateLimiterDoesNotChangeAnything() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter();
        List<Integer> invocationNumbers = new ArrayList<>();

        rateLimiter.reset();

        rateLimiter.execute("subject", () -> invocationNumbers.add(0));
        rateLimiter.execute("subject", () -> invocationNumbers.add(1));

        assertThat(invocationNumbers).containsExactly(0);
    }

    @Test
    void resetClearsAllSubjects() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter();
        List<String> executed = new ArrayList<>();
        rateLimiter.execute("first", () -> executed.add("first"));
        rateLimiter.execute("second", () -> executed.add("second"));

        rateLimiter.reset();
        executed.clear();

        rateLimiter.execute("first", () -> executed.add("first"));
        rateLimiter.execute("second", () -> executed.add("second"));

        assertThat(executed).containsExactly("first", "second");
    }

    @Test
    void whenExecutedConcurrentlyRunnableIsExecutedExactlyOnce() throws Exception {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter();
        AtomicInteger executionCount = new AtomicInteger();
        int threadCount = 16;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        try {
            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        start.await();
                        rateLimiter.execute("subject", executionCount::incrementAndGet);
                    }
                    catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
        }
        finally {
            executor.shutdownNow();
        }

        assertThat(executionCount.get()).isEqualTo(1);
    }

    // region limit on number of subjects
    @Test
    void numberOfRememberedSubjectsIsLimited() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter(3);
        List<Integer> invocationNumbers = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            rateLimiter.execute("subject" + i, () -> {});
        }

        // Adding a fourth subject evicts the least recently used one ("subject0")
        rateLimiter.execute("subject3", () -> {});

        rateLimiter.execute("subject0", () -> invocationNumbers.add(0));
        assertThat(invocationNumbers).containsExactly(0);
    }

    @Test
    void whenLimitIsExceededRecentlyUsedSubjectsAreRetained() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter(3);
        List<String> executed = new ArrayList<>();
        rateLimiter.execute("first", () -> {});
        rateLimiter.execute("second", () -> {});
        rateLimiter.execute("third", () -> {});

        // Touch "first", so it becomes the most recently used and "second" the least recently used.
        rateLimiter.execute("first", () -> executed.add("first"));
        rateLimiter.execute("fourth", () -> executed.add("fourth"));

        // "third" and "first" are still remembered, only the least recently used ("second") has been forgotten.
        rateLimiter.execute("third", () -> executed.add("third"));
        rateLimiter.execute("first", () -> executed.add("first again"));
        assertThat(executed).containsExactly("fourth");

        rateLimiter.execute("second", () -> executed.add("second"));
        assertThat(executed).containsExactly("fourth", "second");
    }

    @Test
    void memoryUsageDoesNotGrowWithNumberOfDistinctSubjects() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter(10);
        AtomicInteger executionCount = new AtomicInteger();

        for (int i = 0; i < 100_000; i++) {
            rateLimiter.execute("subject" + i, executionCount::incrementAndGet);
        }

        assertThat(executionCount.get()).isEqualTo(100_000);
        // And the last 10 subjects are still remembered
        for (int i = 99_990; i < 100_000; i++) {
            rateLimiter.execute("subject" + i, executionCount::incrementAndGet);
        }
        assertThat(executionCount.get()).isEqualTo(100_000);
    }

    @Test
    void maxSubjectsMustBePositive() {
        assertThatThrownBy(() -> new OneShotRateLimiter(0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OneShotRateLimiter(-1)).isInstanceOf(IllegalArgumentException.class);
    }
    // endregion

    @Test
    void whenRunnableThrowsSubjectIsStillMarkedAsExecuted() {
        OneShotRateLimiter rateLimiter = new OneShotRateLimiter();
        List<Integer> invocationNumbers = new ArrayList<>();

        try {
            rateLimiter.execute("subject", () -> { throw new RuntimeException("failing runnable"); });
        }
        catch (RuntimeException expected) {
        }

        rateLimiter.execute("subject", () -> invocationNumbers.add(1));

        assertThat(invocationNumbers).isEmpty();
    }
}
