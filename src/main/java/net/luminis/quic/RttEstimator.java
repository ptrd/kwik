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

import java.time.Duration;
import java.time.Instant;


public class RttEstimator {

    private Logger log;
    // All intervals are in milliseconds (1/1000 second)
    private int initialRtt = 100;
    private int minRtt = Integer.MAX_VALUE;
    private int smoothedRtt = 0;
    private int rttVar;


    public RttEstimator(Logger log) {
        this.log = log;
    }

    public void addSample(Instant timeReceived, Instant timeSent, int ackDelay) {
        if (timeReceived.isBefore(timeSent)) {
            throw new IllegalArgumentException();
        }
        // TODO: if ackDelay > maxAckDelay, limit it to ackDelay.

        int previousSmoothed = smoothedRtt;

        int rttSample = Duration.between(timeSent, timeReceived).getNano() / 1_000_000 - ackDelay;
        if (rttSample < minRtt)
            minRtt = rttSample;
        // Adjust for ack delay if it's plausible.
        if (rttSample > minRtt + ackDelay) {
            rttSample -= ackDelay;
        }

        if (smoothedRtt == 0) {
            // First time
            smoothedRtt = rttSample;
            rttVar = rttSample / 2;
        }
        else {
            int currentRttVar = Math.abs(smoothedRtt - rttSample);
            rttVar = 3 * rttVar / 4 + currentRttVar / 4;
            smoothedRtt = 7 * smoothedRtt / 8 + rttSample / 8;
        }

        log.debug("RTT: " + previousSmoothed + " + " + rttSample + " -> " + smoothedRtt);
    }

    public int getSmoothedRtt() {
        if (smoothedRtt == 0) {
            return initialRtt;
        }
        else {
            return smoothedRtt;
        }
    }
}
