/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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
package net.luminis.quic.recovery;

import net.luminis.quic.core.EncryptionLevel;
import net.luminis.quic.core.MockPacket;
import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.test.FieldSetter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class RttEstimatorTest {

    private static Logger logger;
    private RttEstimator rttEstimator;

    @BeforeAll
    static void initLogger() {
        logger = mock(Logger.class);
    }

    @BeforeEach
    void initObjectUnderTest() {
        rttEstimator = new RttEstimator(logger);
    }

    @Test
    void checkInitialRtt() {
        assertThat(rttEstimator.getSmoothedRtt()).isEqualTo(500);
    }

    @Test
    void afterOneSampleSrttShouldEqualSampleRtt() {
        Instant start = Instant.now();
        Instant end = start.plusMillis(153);
        rttEstimator.addSample(end, start, 0);
        assertThat(rttEstimator.getSmoothedRtt()).isEqualTo(153);
    }

    @Test
    void afterTwoSamplesSrttShouldBeInBetween() {
        Instant start = Instant.now();
        Instant end = start.plusMillis(153);
        rttEstimator.addSample(end, start, 0);
        start = Instant.now();
        end = start.plusMillis(108);
        rttEstimator.addSample(end, start, 0);
        assertThat(rttEstimator.getSmoothedRtt()).isLessThan(153).isGreaterThan(108);
    }

    @Test
    void ackDelayShouldBeSubtractedFromRtt() throws Exception {
        FieldSetter.setField(rttEstimator, rttEstimator.getClass().getDeclaredField("minRtt"), 100);
        rttEstimator.setMaxAckDelay(100);
        Instant start = Instant.now();
        Instant end = start.plusMillis(253);
        rttEstimator.addSample(end, start, 80);
        assertThat(rttEstimator.getSmoothedRtt()).isEqualTo(173);
    }

    @Test
    void rttVarShouldNeverBecomeZero() {
        Instant start = Instant.now();
        Instant end = start.plusMillis(10);
        // Simulate number of samples with the exact same rtt
        for (int i = 0; i < 10; i++) {
            rttEstimator.addSample(end, start, 0);
        }

        assertThat(rttEstimator.getRttVar()).isGreaterThan(0);
    }

    @Test
    void whenNoNewlyAckedRttEstimateIsNotUpdated() {
        rttEstimator.ackReceived(new AckFrame(0), Instant.now(), Collections.emptyList());

        assertThat(rttEstimator.getSmoothedRtt()).isEqualTo(500);
    }

    @Test
    void newlyAckedUpdatesRttEstimate() {
        Instant start = Instant.now();
        Instant end = start.plusMillis(10);
        rttEstimator.ackReceived(new AckFrame(9), end, List.of(new PacketStatus(start, new MockPacket(9, 120, ""), null)));

        assertThat(rttEstimator.getLatestRtt()).isEqualTo(10);
    }

    @Test
    void whenLargestIsNotNewlyAckedRttEstimateIsNotUpdated() {
        Instant start = Instant.now();
        Instant end = start.plusMillis(10);
        rttEstimator.ackReceived(new AckFrame(9), end, List.of(new PacketStatus(start, new MockPacket(8, 120, ""), null)));

        assertThat(rttEstimator.getSmoothedRtt()).isEqualTo(500);
    }

    @Test
    void whenNewlyAckedIsNotAckElicitingRttEstimateIsNotUpdated() {
        Instant start = Instant.now();
        Instant end = start.plusMillis(10);
        rttEstimator.ackReceived(new AckFrame(9), end, List.of(new PacketStatus(start, new MockPacket(9, 120, EncryptionLevel.App, new AckFrame(4)), null)));

        assertThat(rttEstimator.getSmoothedRtt()).isEqualTo(500);
    }

    @Test
    void latestRttCanNeverBeSmallerThanMinRtt() {
        // Given
        Instant t0 = Instant.now();
        Instant t1 = t0.plusMillis(10);
        Instant t2 = t1.plusMillis(10);

        rttEstimator.addSample(t1, t0, 0);

        // When
        rttEstimator.addSample(t2, t1, 20);

        // Then
        assertThat(rttEstimator.getLatestRtt()).isEqualTo(10);
    }

    @Test
    void whenAckDelayGreaterThanMaxLimitIt() throws Exception {
        // Given
        FieldSetter.setField(rttEstimator, rttEstimator.getClass().getDeclaredField("minRtt"), 100);
        rttEstimator.setMaxAckDelay(50);

        // When
        Instant start = Instant.now();
        Instant end = start.plusMillis(253);
        rttEstimator.addSample(end, start, 80);

        // Then
        assertThat(rttEstimator.getSmoothedRtt()).isEqualTo(203);
    }

    @Test
    void evenWithSmallRttSamplesSmoothedRttShouldNotBecomeLessThenMinRtt() throws Exception {
        for (int i = 0; i < 10; i++) {
            Instant start = Instant.now();
            Instant end = start.plusMillis(6);
            rttEstimator.addSample(end, start, 0);
            assertThat(rttEstimator.getSmoothedRtt()).isGreaterThanOrEqualTo(6);
        }
        for (int i = 0; i < 10; i++) {
            Instant start = Instant.now();
            Instant end = start.plusMillis(4);
            rttEstimator.addSample(end, start, 0);
            assertThat(rttEstimator.getSmoothedRtt()).isGreaterThanOrEqualTo(4);
        }
        for (int i = 0; i < 10; i++) {
            Instant start = Instant.now();
            Instant end = start.plusMillis(1);
            rttEstimator.addSample(end, start, 0);
            assertThat(rttEstimator.getSmoothedRtt()).isGreaterThanOrEqualTo(1);
        }
    }

    @Test
    void evenWithSmallRttSamplesRttVarShouldNotBeRoundedToZero() throws Exception {
        for (int i = 0; i < 10; i++) {
            Instant start = Instant.now();
            int rtt = (i / 3 % 2) == 0 ? 8 : 3;
            Instant end = start.plusMillis(rtt);
            rttEstimator.addSample(end, start, 0);
            assertThat(rttEstimator.getRttVar()).isGreaterThanOrEqualTo(1);
        }
    }

    @Test
    void smoothedRttShouldBeRoundedUpToNearestInteger() throws Exception {
        for (int rtt: new int[] { 3, 10 } ) {
            Instant start = Instant.now();
            Instant end = start.plusMillis(rtt);
            rttEstimator.addSample(end, start, 0);
        }
        //  rtt:      3, 8
        //  smoothed: 3, 3.875
        assertThat(rttEstimator.getSmoothedRtt()).isGreaterThan(3);
    }

    @Test
    void smoothedRttShouldBeRoundedDownToNearestInteger() throws Exception {
        for (int rtt: new int[] { 3, 6 } ) {
            Instant start = Instant.now();
            Instant end = start.plusMillis(rtt);
            rttEstimator.addSample(end, start, 0);
        }
        //  rtt:      3, 6
        //  smoothed: 3, 3.375
        assertThat(rttEstimator.getSmoothedRtt()).isEqualTo(3);
    }

    @Test
    void registerSamplesWithDurationLargerThenOneSecondCorrectly() {
        Instant start = Instant.now();
        Instant end = start.plusMillis(1016);
        rttEstimator.addSample(end, start,0);

        assertThat(rttEstimator.getSmoothedRtt()).isGreaterThan(1000);
    }
}