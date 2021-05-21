/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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
package net.luminis.quic.util;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


class ProgressivelyIncreasingRateLimiterTest {

    @Test
    void firstAndSecondAreExecuted() {
        ProgressivelyIncreasingRateLimiter rateLimiter = new ProgressivelyIncreasingRateLimiter();
        List<Integer> invocationNumbers = new ArrayList();
        rateLimiter.execute(() -> invocationNumbers.add(0));
        rateLimiter.execute(() -> invocationNumbers.add(1));
        assertThat(invocationNumbers).containsExactly(0, 1);
    }

    @Test
    void rateIsLimitedToPowersOfTwo() {
        ProgressivelyIncreasingRateLimiter rateLimiter = new ProgressivelyIncreasingRateLimiter();
        List<Integer> invocationNumbers = new ArrayList();
        for (int i = 1; i < 100; i++) {
            int index = i;
            rateLimiter.execute(() -> invocationNumbers.add(index));
        }
        assertThat(invocationNumbers).containsExactly(1, 2, 4, 8, 16, 32, 64);
    }

    @Test
    void afterResetRateIsLimitedToPowersOfTwo() {
        ProgressivelyIncreasingRateLimiter rateLimiter = new ProgressivelyIncreasingRateLimiter();
        List<Integer> invocationNumbers = new ArrayList();
        rateLimiter.execute(() -> invocationNumbers.add(0));
        rateLimiter.execute(() -> invocationNumbers.add(1));

        rateLimiter.reset();
        invocationNumbers.clear();
        for (int i = 1; i < 100; i++) {
            int index = i;
            rateLimiter.execute(() -> invocationNumbers.add(index));
        }
        assertThat(invocationNumbers).containsExactly(1, 2, 4, 8, 16, 32, 64);
    }

}