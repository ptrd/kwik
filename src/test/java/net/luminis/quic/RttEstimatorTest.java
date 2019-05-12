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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class RttEstimatorTest {

    private static Logger logger;
    private RttEstimator rttEstimator;

    @BeforeAll
    static void initLogger() {
        logger = mock(Logger.class);
    }

    @Test
    void checkInitialRtt() {
        rttEstimator = new RttEstimator(logger);
        assertThat(rttEstimator.getSmoothedRtt()).isEqualTo(500);
    }

    @Test
    void afterOneSampleSrttShouldEqualSampleRtt() {
        rttEstimator = new RttEstimator(logger);
        Instant start = Instant.now();
        Instant end = start.plusMillis(153);
        rttEstimator.addSample(end, start, 0);
        assertThat(rttEstimator.getSmoothedRtt()).isEqualTo(153);
    }

    @Test
    void afterTwoSamplesSrttShouldBeInBetween() {
        rttEstimator = new RttEstimator(logger);
        Instant start = Instant.now();
        Instant end = start.plusMillis(153);
        rttEstimator.addSample(end, start, 0);
        start = Instant.now();
        end = start.plusMillis(108);
        rttEstimator.addSample(end, start, 0);
        assertThat(rttEstimator.getSmoothedRtt()).isLessThan(153).isGreaterThan(108);
    }

    @Test
    void ackDelayShouldBeSubtractedFromRtt() {
        rttEstimator = new RttEstimator(logger);
        Instant start = Instant.now();
        Instant end = start.plusMillis(253);
        rttEstimator.addSample(end, start, 80);
        assertThat(rttEstimator.getSmoothedRtt()).isEqualTo(173);
    }

    @Test
    void rttVarShouldNeverBecomeZero() {
        rttEstimator = new RttEstimator(logger);
        Instant start = Instant.now();
        Instant end = start.plusMillis(10);
        // Simulate number of samples with the exact same rtt
        for (int i = 0; i < 10; i++) {
            rttEstimator.addSample(end, start, 0);
        }

        assertThat(rttEstimator.getRttVar()).isGreaterThan(0);
    }
}