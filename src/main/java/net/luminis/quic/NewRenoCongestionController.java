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

import java.time.Instant;
import java.util.List;
import java.util.Optional;

// https://tools.ietf.org/html/draft-ietf-quic-recovery-23#section-6
// "QUIC's congestion control is based on TCP NewReno [RFC6582]."
public class NewRenoCongestionController extends AbstractCongestionController implements CongestionController {

    public enum Mode {
        SlowStart,
        CongestionAvoidance
    };

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-23#appendix-B.1
    // "Reduction in congestion window when a new loss event is detected.  The RECOMMENDED value is 0.5."
    protected int kLossReductionFactor = 2;

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-23#appendix-B.1
    // "Minimum congestion window in bytes.  The RECOMMENDED value is 2 * kMaxDatagramSize."
    protected int kMinimumWindow = 2 * 1200;

    private long slowStartThreshold = Long.MAX_VALUE;
    private Instant congestionRecoveryStartTime;

    public NewRenoCongestionController(Logger logger) {
        super(logger);
        congestionRecoveryStartTime = Instant.MIN;
    }

    @Override
    public synchronized void registerAcked(PacketInfo acknowlegdedPacket) {
        // https://tools.ietf.org/html/draft-ietf-quic-recovery-23#section-6.4
        // "it defines the end of recovery as a packet sent after the start of recovery being acknowledged"
        if (acknowlegdedPacket.timeSent.isAfter(congestionRecoveryStartTime)) {
            super.registerAcked(acknowlegdedPacket);
            congestionWindow += acknowlegdedPacket.packet.getSize();
        }
    }

    @Override
    public void registerLost(List<? extends PacketInfo> lostPackets) {
        super.registerLost(lostPackets);

        PacketInfo largest = lostPackets.stream().max((p1, p2) -> p1.packet.getPacketNumber().compareTo(p2.packet.getPacketNumber())).get();

        fireCongestionEvent(largest.timeSent);
    }

    public Mode getMode() {
        if (congestionWindow < slowStartThreshold) {
            return Mode.SlowStart;
        }
        else {
            return Mode.CongestionAvoidance;
        }
    }

    private void fireCongestionEvent(Instant timeSent) {
        if (timeSent.isAfter(congestionRecoveryStartTime)) {
            congestionRecoveryStartTime = Instant.now();
            congestionWindow /= kLossReductionFactor;
            if (congestionWindow < kMinimumWindow) {
                congestionWindow = kMinimumWindow;
            }
            slowStartThreshold = congestionWindow;
        }
    }

}

