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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A rate limiter that allows a given runnable to be executed only once for a given subject or context.
 * Subsequent attempts to execute the runnable with the same subject will be ignored.
 *
 * As the number of distinct subjects can be unbounded (e.g. when the subject is derived from data controlled by a
 * peer), the number of subjects remembered is limited. When the limit is reached, the least recently used subject is
 * forgotten, which implies the runnable can be executed again for that subject.
 */
public class OneShotRateLimiter implements RateLimiter {

    public static final int DEFAULT_MAX_SUBJECTS = 100;

    private final int maxSubjects;
    private final Map<Object, Boolean> executedSubjects;
    private final ReentrantLock executedSubjectsLock = new ReentrantLock();

    public OneShotRateLimiter() {
        this(DEFAULT_MAX_SUBJECTS);
    }

    public OneShotRateLimiter(int maxSubjects) {
        if (maxSubjects < 1) {
            throw new IllegalArgumentException("maxSubjects must be at least 1");
        }
        this.maxSubjects = maxSubjects;
        // Access ordered, so the least recently used subject is evicted when the maximum is exceeded.
        executedSubjects = new LinkedHashMap<>(4, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Object, Boolean> eldest) {
                return size() > OneShotRateLimiter.this.maxSubjects;
            }
        };
    }

    @Override
    public void execute(Runnable runnable) {
    }

    public void execute(Object subject, Runnable runnable) {
        Objects.requireNonNull(subject);
        boolean notExecutedBefore;
        executedSubjectsLock.lock();
        try {
            notExecutedBefore = executedSubjects.put(subject, Boolean.TRUE) == null;
        }
        finally {
            executedSubjectsLock.unlock();
        }
        if (notExecutedBefore) {
            runnable.run();
        }
    }

    @Override
    public void reset() {
        executedSubjectsLock.lock();
        try {
            executedSubjects.clear();
        }
        finally {
            executedSubjectsLock.unlock();
        }
    }
}
