/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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

import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.recovery.PacketStatus;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;


public class RttEstimator {

    private static final int NOT_SET = -1;

    private final Logger log;
    // All intervals are in milliseconds (1/1000 second)
    private volatile int initialRtt;
    private volatile int minRtt = Integer.MAX_VALUE;
    private volatile int smoothedRtt = NOT_SET;
    private volatile int rttVar = NOT_SET;
    private volatile int latestRtt;
    private volatile int maxAckDelay;


    public RttEstimator(Logger log) {
        this.log = log;

        // https://tools.ietf.org/html/draft-ietf-quic-recovery-20#section-6.2
        // "If no previous RTT is available, or if the network
        //   changes, the initial RTT SHOULD be set to 500ms"
        initialRtt = 500;

        // https://tools.ietf.org/html/draft-ietf-quic-transport-30#section-8.2
        // "If this value is absent, a default of 25 milliseconds is assumed."
        maxAckDelay = 25;
    }

    public RttEstimator(Logger log, int initialRtt) {
        this.log = log;
        this.initialRtt = initialRtt;
    }

    public void addSample(Instant timeReceived, Instant timeSent, int ackDelay) {
        if (timeReceived.isBefore(timeSent)) {
            // This sometimes happens in the Interop runner; reconsider solution after new sender is implemented.
            log.error("Receiving negative rtt estimate: sent=" + timeSent + ", received=" + timeReceived);
            return;
        }

        if (ackDelay > maxAckDelay) {
            ackDelay = maxAckDelay;
        }

        int previousSmoothed = smoothedRtt;

        int rttSample = Duration.between(timeSent, timeReceived).getNano() / 1_000_000;
        if (rttSample < minRtt)
            minRtt = rttSample;
        // Adjust for ack delay if it's plausible. Because times are truncated at millisecond precision,
        // consider rtt equal to min as plausible.
        if (rttSample >= minRtt + ackDelay) {
            rttSample -= ackDelay;
        }
        latestRtt = rttSample;

        if (smoothedRtt == NOT_SET) {
            // First time
            smoothedRtt = rttSample;
            rttVar = rttSample / 2;
        }
        else {
            int currentRttVar = Math.abs(smoothedRtt - rttSample);
            rttVar = (3 * rttVar + currentRttVar + 2) / 4;        // Add 2 to round to nearest integer
            smoothedRtt = (7 * smoothedRtt + rttSample + 4) / 8;  // Add 4 to round to nearest integer
        }

        log.debug("RTT: " + previousSmoothed + " + " + rttSample + " -> " + smoothedRtt);
    }

    public int getSmoothedRtt() {
        if (smoothedRtt == NOT_SET) {
            return initialRtt;
        }
        else {
            return smoothedRtt;
        }
    }

    public int getRttVar() {
        // Rtt-var is only used for computing PTO.
        // https://tools.ietf.org/html/draft-ietf-quic-recovery-23#section-5.3
        // "The initial probe timeout for a new connection or new path SHOULD be set to twice the initial RTT"
        // https://tools.ietf.org/html/draft-ietf-quic-recovery-23#section-5.2.1
        // "PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay"
        // Hence, using an initial rtt-var of initial-rtt / 4, will result in an initial PTO of twice the initial RTT.
        // After the first packet is received, the rttVar will be computed from the real RTT sample.
        if (rttVar == NOT_SET) {
            return initialRtt / 4;
        }
        else {
            return rttVar;
        }
    }

    public void ackReceived(AckFrame ack, Instant timeReceived, List<PacketStatus> newlyAcked) {
        // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-5.1
        // "An endpoint generates an RTT sample on receiving an ACK frame that meets the following two conditions:
        //   *  the largest acknowledged packet number is newly acknowledged, and
        //   *  at least one of the newly acknowledged packets was ack-eliciting."
        Optional<PacketStatus> largestAcked = newlyAcked.stream()
                .filter(s -> s.packet().getPacketNumber() == ack.getLargestAcknowledged())  // Possible optimization: isn't newlyAcked sorted, so only checking first will do?
                .findFirst();
        if (largestAcked.isPresent()) {
            if (newlyAcked.stream().anyMatch(s -> s.packet().isAckEliciting())) {
                addSample(timeReceived, largestAcked.get().timeSent(), ack.getAckDelay());
            }
        }
    }

    public int getLatestRtt() {
        return latestRtt;
    }

    public void setMaxAckDelay(int maxAckDelay) {
        this.maxAckDelay = maxAckDelay;
    }
}
