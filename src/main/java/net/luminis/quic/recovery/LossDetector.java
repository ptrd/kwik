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

import net.luminis.quic.cc.CongestionController;
import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.packet.PacketInfo;
import net.luminis.quic.packet.QuicPacket;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Collectors;


public class LossDetector {

    private final RecoveryManager recoveryManager;
    private final RttEstimator rttEstimater;
    private final CongestionController congestionController;
    private final Runnable postProcessLostCallback;
    private float kTimeThreshold = 9f/8f;
    private int kPacketThreshold = 3;
    private final Map<Long, PacketStatus> packetSentLog;
    private final AtomicInteger ackElicitingInFlight;
    private volatile long largestAcked = -1;
    private volatile long lost;
    private volatile Instant lossTime;
    private volatile Instant lastAckElicitingSent;
    private volatile boolean isReset;


    public LossDetector(RecoveryManager recoveryManager, RttEstimator rttEstimator, CongestionController congestionController, Runnable postProcessLostCallback) {
        this.recoveryManager = recoveryManager;
        this.rttEstimater = rttEstimator;
        this.congestionController = congestionController;
        this.postProcessLostCallback = postProcessLostCallback;

        ackElicitingInFlight = new AtomicInteger();
        packetSentLog = new ConcurrentHashMap<>();
    }

    public synchronized void packetSent(QuicPacket packet, Instant sent, Consumer<QuicPacket> lostPacketCallback) {
        if (isReset) {
            return;
        }

        if (packet.isInflightPacket()) {  // Redundant: caller checked
            congestionController.registerInFlight(packet);
        }

        if (packet.isAckEliciting()) {
            ackElicitingInFlight.getAndAdd(1);
            lastAckElicitingSent = sent;
        }

        // This method is synchronized, because during a reset operation, no new packets must be logged as sent.
        packetSentLog.put(packet.getPacketNumber(), new PacketStatus(sent, packet, lostPacketCallback));
    }

    public void onAckReceived(AckFrame ackFrame, Instant timeReceived) {
        if (isReset) {
            return;
        }

        largestAcked = Long.max(largestAcked, ackFrame.getLargestAcknowledged());

        List<PacketStatus> newlyAcked = ackFrame.getAckedPacketNumbers()
                .filter(pn -> packetSentLog.containsKey(pn) && !packetSentLog.get(pn).acked())
                .map(pn -> packetSentLog.get(pn))
                .filter(packetStatus -> packetStatus != null)      // Could be null when reset is executed concurrently.
                .filter(packetStatus -> packetStatus.setAcked())   // Only keep the ones that actually got set to acked
                .collect(Collectors.toList());

        // Possible optimization: everything that follows only if newlyAcked not empty

        int ackedAckEliciting = (int) newlyAcked.stream().filter(packetStatus -> packetStatus.packet().isAckEliciting()).count();
        assert ackedAckEliciting <= ackElicitingInFlight.get();
        ackElicitingInFlight.getAndAdd(-1 * ackedAckEliciting);

        congestionController.registerAcked(filterInFlight(newlyAcked));

        detectLostPackets();

        recoveryManager.setLossDetectionTimer();

        rttEstimater.ackReceived(ackFrame, timeReceived, newlyAcked);

        // Cleanup
        newlyAcked.stream().forEach(p -> packetSentLog.remove(p.packet().getPacketNumber()));
    }

    public synchronized void reset() {
        List<PacketStatus> inflightPackets = packetSentLog.values().stream()
                .filter(packet -> packet.inFlight())
                .filter(packetStatus -> packetStatus.setLost())   // Only keep the ones that actually were set to lost
                .collect(Collectors.toList());
        congestionController.discard(inflightPackets);
        ackElicitingInFlight.set(0);
        packetSentLog.clear();
        lossTime = null;
        lastAckElicitingSent = null;
        isReset = true;
    }

    void detectLostPackets() {
        if (isReset) {
            return;
        }

        int lossDelay = (int) (kTimeThreshold * Integer.max(rttEstimater.getSmoothedRtt(), rttEstimater.getLatestRtt()));
        assert(lossDelay > 0);  // Minimum time of kGranularity before packets are deemed lost
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
        else {
            lossTime = null;
        }
    }

    Instant getLossTime() {
        return lossTime;
    }

    Instant getLastAckElicitingSent() {
        return lastAckElicitingSent;
    }

    boolean ackElicitingInFlight() {
        int actualAckElicitingInFlight = ackElicitingInFlight.get();
        assert actualAckElicitingInFlight >= 0;
        return actualAckElicitingInFlight != 0;
    }

    List<QuicPacket> unAcked() {
        return packetSentLog.values().stream()
                .filter(p -> p.inFlight())
                .filter(p -> !p.packet().isAckOnly())
                .map(p -> p.packet())
                .collect(Collectors.toList());
    }

    // For debugging only
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

        int lostAckEliciting = (int) lostPacketsInfo.stream().filter(packetStatus -> packetStatus.packet().isAckEliciting()).count();
        assert lostAckEliciting <= ackElicitingInFlight.get();
        ackElicitingInFlight.getAndAdd(-1 * lostAckEliciting);

        lostPacketsInfo.stream()
                .forEach(packetStatus -> {
                    // Retransmitting the frames in the lost packet is delegated to the lost frame callback, because
                    // whether retransmitting the frame is necessary (and in which manner) depends on frame type,
                    // see https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-13.3
                    packetStatus.lostPacketCallback().accept(packetStatus.packet());
                    lost++;
                });
        postProcessLostCallback.run();

        congestionController.registerLost(filterInFlight(lostPacketsInfo));

        // Cleanup
        lostPacketsInfo.stream().forEach(p -> packetSentLog.remove(p.packet().getPacketNumber()));
    }

    private List<PacketStatus> filterInFlight(List<PacketStatus> packets) {
        return packets.stream()
                .filter(packetInfo -> packetInfo.packet().isInflightPacket())
                .collect(Collectors.toList());
    }

    public long getLost() {
        return lost;
    }

    public boolean noAckedReceived() {
        return largestAcked < 0;
    }

}
