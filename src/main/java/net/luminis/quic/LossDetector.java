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
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.stream.Collectors;


public class LossDetector {

    private final RecoveryManager recoveryManager;
    private final RttEstimator rttEstimater;
    private final CongestionController congestionController;
    private float kTimeThreshold = 9f/8f;
    private int kPacketThreshold = 3;
    private final Map<Long, PacketAckStatus> packetSentLog;
    private volatile long largestAcked;
    private volatile long lost;
    private volatile Instant lossTime;


    public LossDetector(RecoveryManager recoveryManager, RttEstimator rttEstimator, CongestionController congestionController) {
        this.recoveryManager = recoveryManager;
        this.rttEstimater = rttEstimator;
        this.congestionController = congestionController;
        packetSentLog = new ConcurrentHashMap<>();
    }

    public void packetSent(QuicPacket packet, Instant sent, Consumer<QuicPacket> lostPacketCallback) {
        packetSentLog.put(packet.getPacketNumber(), new PacketAckStatus(sent, packet, lostPacketCallback));
    }

    public void onAckReceived(AckFrame ackFrame) {
        largestAcked = Long.max(largestAcked, ackFrame.getLargestAcknowledged());
        ackFrame.getAckedPacketNumbers().stream().forEach(pn -> {
            if (packetSentLog.containsKey(pn) && !packetSentLog.get(pn).acked) {
                packetSentLog.get(pn).acked = true;
                congestionController.registerAcked(packetSentLog.get(pn).packet);
            }
            else if (!packetSentLog.containsKey(pn)) {
                // Incorrect ack received.
            }
        });

        detectLostPackets();

        recoveryManager.setLossDetectionTimer();
    }

    void detectLostPackets() {
        lossTime = null;

        int lossDelay = (int) (kTimeThreshold * Integer.max(rttEstimater.getSmoothedRtt(), rttEstimater.getLatestRtt()));
        Instant lostSendTime = Instant.now().minusMillis(lossDelay);

        // https://tools.ietf.org/html/draft-ietf-quic-recovery-20#section-6.1
        // "A packet is declared lost if it meets all the following conditions:
        //   o  The packet is unacknowledged, in-flight, and was sent prior to an
        //      acknowledged packet.
        //   o  Either its packet number is kPacketThreshold smaller than an
        //      acknowledged packet (Section 6.1.1), or it was sent long enough in
        //      the past (Section 6.1.2)."
        // https://tools.ietf.org/html/draft-ietf-quic-recovery-20#section-2
        // "In-flight:  Packets are considered in-flight when they have been sent
        //      and neither acknowledged nor declared lost, and they are not ACK-
        //      only."
        packetSentLog.values().stream()
                .filter(p -> !p.acked && !p.lost)
                .filter(p -> pnTooOld(p) || sentTimeTooLongAgo(p, lostSendTime))
                .filter(p -> !p.packet.isAckOnly())
                .forEach(p -> declareLost(p));

        Optional<Instant> earliestSentTime = packetSentLog.values().stream()
                .filter(p -> !p.acked && !p.lost)
                .filter(p -> p.packet.getPacketNumber() <= largestAcked)
                .filter(p -> !p.packet.isAckOnly())
                .map(p -> p.timeSent)
                .min(Instant::compareTo);

        if (earliestSentTime.isPresent() && earliestSentTime.get().isAfter(lostSendTime)) {
            lossTime = earliestSentTime.get().plusMillis(lossDelay);
        }
    }

    Instant getLossTime() {
        return lossTime;
    }

    boolean ackElicitingInFlight() {
        boolean inflight = packetSentLog.values().stream()
                    .filter(p -> p.packet.isAckEliciting())
                    .filter(p -> !p.acked && !p.lost)
                    .findFirst()
                    .isPresent();
        return inflight;
    }

    List<QuicPacket> unAcked() {
        return packetSentLog.values().stream()
                .filter(p -> !p.acked && !p.lost)
                .filter(p -> !p.packet.isAckOnly())
                .map(p -> p.packet)
                .collect(Collectors.toList());
    }

    // For debugging
    List<PacketAckStatus> getInFlight() {
        return packetSentLog.values().stream()
                .filter(p -> p.packet.isAckEliciting())
                .filter(p -> !p.acked && !p.lost)
                .collect(Collectors.toList());
    }


    private boolean pnTooOld(PacketAckStatus p) {
        return p.packet.getPacketNumber() <= largestAcked - kPacketThreshold;
    }

    private boolean sentTimeTooLongAgo(PacketAckStatus p, Instant lostSendTime) {
        return p.packet.getPacketNumber() <= largestAcked && p.timeSent.isBefore(lostSendTime);
    }

    private void declareLost(PacketAckStatus packetAckStatus) {
        packetAckStatus.lostPacketCallback.accept(packetAckStatus.packet);
        packetAckStatus.lost = true;
        lost++;
        congestionController.registerLost(packetAckStatus.packet);
    }

    public void reset() {
        packetSentLog.clear();
        lossTime = null;
    }

    public long getLost() {
        return lost;
    }

    private static class PacketAckStatus {
        final Instant timeSent;
        final QuicPacket packet;
        private final Consumer<QuicPacket> lostPacketCallback;
        public boolean lost;
        boolean acked;

        public PacketAckStatus(Instant sent, QuicPacket packet, Consumer<QuicPacket> lostPacketCallback) {
            this.timeSent = sent;
            this.packet = packet;
            this.lostPacketCallback = lostPacketCallback;
        }

        public String status() {
            if (acked) {
                return "Acked";
            } else if (lost) {
                return "Resent";
            } else {
                return "-";
            }
        }

        public Instant timeSent() {
            return timeSent;
        }

        @Override
        public String toString() {
            return "Packet "
                + packet.getEncryptionLevel().name().charAt(0) + "|"
                + (packet.packetNumber >= 0? packet.packetNumber: ".") + "|"
                + "L" + "|" + status();
        }

    }
}
