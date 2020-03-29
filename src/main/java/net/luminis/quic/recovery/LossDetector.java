/*
 * Copyright © 2019, 2020 Peter Doornbosch
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
package net.luminis.quic.recovery;

import net.luminis.quic.CongestionController;
import net.luminis.quic.RttEstimator;
import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.packet.PacketInfo;
import net.luminis.quic.packet.QuicPacket;

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
    private final Map<Long, PacketStatus> packetSentLog;
    private volatile long largestAcked = -1;
    private volatile long lost;
    private volatile Instant lossTime;
    private volatile Instant lastAckElicitingSent;


    public LossDetector(RecoveryManager recoveryManager, RttEstimator rttEstimator, CongestionController congestionController) {
        this.recoveryManager = recoveryManager;
        this.rttEstimater = rttEstimator;
        this.congestionController = congestionController;
        packetSentLog = new ConcurrentHashMap<>();
    }

    public void packetSent(QuicPacket packet, Instant sent, Consumer<QuicPacket> lostPacketCallback) {
        if (packet.isAckEliciting()) {
            lastAckElicitingSent = sent;
        }
        packetSentLog.put(packet.getPacketNumber(), new PacketStatus(sent, packet, lostPacketCallback));
    }

    public void onAckReceived(AckFrame ackFrame) {
        largestAcked = Long.max(largestAcked, ackFrame.getLargestAcknowledged());

        List<PacketStatus> newlyAcked = ackFrame.getAckedPacketNumbers().stream()
                .filter(pn -> packetSentLog.containsKey(pn) && !packetSentLog.get(pn).acked())
                .map(pn -> packetSentLog.get(pn))
                .filter(packetStatus -> packetStatus.setAcked())   // Only keep the ones that actually got set to acked
                .collect(Collectors.toList());

        congestionController.registerAcked(filterInFlight(newlyAcked));

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
        List<PacketStatus> lostPackets = packetSentLog.values().stream()
                .filter(p -> p.inFlight())
                .filter(p -> pnTooOld(p) || sentTimeTooLongAgo(p, lostSendTime))
                .filter(p -> !p.packet().isAckOnly())
                .collect(Collectors.toList());
        if (!lostPackets.isEmpty()) {
            declareLost(lostPackets);
        }

        Optional<Instant> earliestSentTime = packetSentLog.values().stream()
                .filter(p -> p.inFlight())
                .filter(p -> p.packet().getPacketNumber() <= largestAcked)
                .filter(p -> !p.packet().isAckOnly())
                .map(p -> p.timeSent())
                .min(Instant::compareTo);

        if (earliestSentTime.isPresent() && earliestSentTime.get().isAfter(lostSendTime)) {
            lossTime = earliestSentTime.get().plusMillis(lossDelay);
        }
    }

    Instant getLossTime() {
        return lossTime;
    }

    Instant getLastAckElicitingSent() {
        return lastAckElicitingSent;
    }

    boolean ackElicitingInFlight() {
        boolean inflight = packetSentLog.values().stream()
                    .filter(p -> p.packet().isAckEliciting())
                    .filter(p -> p.inFlight())
                    .findFirst()
                    .isPresent();
        return inflight;
    }

    List<QuicPacket> unAcked() {
        return packetSentLog.values().stream()
                .filter(p -> p.inFlight())
                .filter(p -> !p.packet().isAckOnly())
                .map(p -> p.packet())
                .collect(Collectors.toList());
    }

    // For debugging
    List<PacketInfo> getInFlight() {
        return packetSentLog.values().stream()
                .filter(p -> !p.packet().isAckOnly())
                .filter(p -> p.inFlight())
                .collect(Collectors.toList());
    }


    private boolean pnTooOld(PacketStatus p) {
        return p.packet().getPacketNumber() <= largestAcked - kPacketThreshold;
    }

    private boolean sentTimeTooLongAgo(PacketStatus p, Instant lostSendTime) {
        return p.packet().getPacketNumber() <= largestAcked && p.timeSent().isBefore(lostSendTime);
    }

    private void declareLost(List<PacketStatus> lostPacketsInfo) {
        lostPacketsInfo = lostPacketsInfo.stream()
                .filter(packetStatus -> packetStatus.setLost())   // Only keep the ones that actually were set to lost
                .collect(Collectors.toList());

        lostPacketsInfo.stream()
                .forEach(packetStatus -> {
                    packetStatus.lostPacketCallback().accept(packetStatus.packet());
                    lost++;
                });

        congestionController.registerLost(lostPacketsInfo);
    }

    public void reset() {
        List<PacketStatus> inflightPackets = packetSentLog.values().stream()
                .filter(packet -> packet.inFlight())
                .filter(packetStatus -> packetStatus.setLost())   // Only keep the ones that actually were set to lost
                .collect(Collectors.toList());
        congestionController.discard(inflightPackets);
        packetSentLog.clear();
        lossTime = null;
        lastAckElicitingSent = null;
    }

    public long getLost() {
        return lost;
    }

    private List<PacketStatus> filterInFlight(List<PacketStatus> packets) {
        return packets.stream()
                .filter(packetInfo -> !packetInfo.packet().isAckOnly())
                .collect(Collectors.toList());
    }

    public boolean noAckedReceived() {
        return largestAcked < 0;
    }

}
