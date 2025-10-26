/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.recovery;

import tech.kwik.core.cc.CongestionController;
import tech.kwik.core.frame.AckFrame;
import tech.kwik.core.log.QLog;
import tech.kwik.core.packet.PacketInfo;
import tech.kwik.core.packet.QuicPacket;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.SortedMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Collectors;


public class LossDetector {

    private final Clock clock;
    private final RecoveryManager recoveryManager;
    private final RttEstimator rttEstimater;
    private final CongestionController congestionController;
    private final Runnable postProcessLostCallback;
    private final QLog qLog;
    private final float kTimeThreshold = 9f/8f;
    private final int kPacketThreshold = 3;
    private final SortedMap<Long, PacketStatus> packetSentLog;
    private final AtomicInteger ackElicitingInFlight;
    private volatile long largestAcked = -1;
    private volatile long lost;
    private volatile Instant lossTime;
    private volatile Instant lastAckElicitingSent;
    private volatile boolean isClosed;


    public LossDetector(RecoveryManager recoveryManager, RttEstimator rttEstimator, CongestionController congestionController, Runnable postProcessLostCallback, QLog qLog) {
        this(Clock.systemUTC(), recoveryManager, rttEstimator, congestionController, postProcessLostCallback, qLog);
    }

    public LossDetector(Clock clock, RecoveryManager recoveryManager, RttEstimator rttEstimator, CongestionController congestionController, Runnable postProcessLostCallback, QLog qLog) {
        this.clock = clock;
        this.recoveryManager = recoveryManager;
        this.rttEstimater = rttEstimator;
        this.congestionController = congestionController;
        this.postProcessLostCallback = postProcessLostCallback;
        this.qLog = qLog;

        ackElicitingInFlight = new AtomicInteger();
        packetSentLog = new ConcurrentSkipListMap<>();
    }

    public synchronized void packetSent(QuicPacket packet, Instant sent, Consumer<QuicPacket> lostPacketCallback) {
        if (isClosed) {
            return;
        }

        // https://www.rfc-editor.org/rfc/rfc9002.html#section-2
        // "Packets are considered in flight when they are ack-eliciting or contain a PADDING frame, and ..."
        assert packet.isInflightPacket();

        congestionController.registerInFlight(packet);

        if (packet.isAckEliciting()) {
            ackElicitingInFlight.getAndAdd(1);
            lastAckElicitingSent = sent;
        }

        // This method is synchronized, because during a reset operation, no new packets must be logged as sent.
        packetSentLog.put(packet.getPacketNumber(), new PacketStatus(sent, packet, lostPacketCallback));
    }

    public void onAckReceived(AckFrame ackFrame, Instant timeReceived) {
        if (isClosed) {
            return;
        }

        largestAcked = Long.max(largestAcked, ackFrame.getLargestAcknowledged());

        List<PacketStatus> newlyAcked = determineNewlyAcked(ackFrame);
        if (newlyAcked.isEmpty()) {
             return;
        }

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

    /**
     * Determine which packets were newly acked by the given AckFrame and mark them as acked.
     * @param ackFrame
     * @return
     */
    private List<PacketStatus> determineNewlyAcked(AckFrame ackFrame) {
        long smallestLoggedPacketNumber = packetSentLog.isEmpty() ? Long.MAX_VALUE : packetSentLog.firstKey();
        return ackFrame.getAckedPacketNumbers(smallestLoggedPacketNumber)
                .map(pn -> packetSentLog.get(pn))
                .filter(packetStatus -> packetStatus != null)      // Could be null if the packet was already removed from the log
                .filter(packetStatus -> !packetStatus.acked())     // Only keep the ones that are not acked yet
                .filter(packetStatus -> packetStatus.setAcked())   // Only keep the ones that actually got set to acked
                .collect(Collectors.toList());
    }

    public synchronized void close() {
        List<PacketStatus> inflightPackets = packetSentLog.values().stream()
                .filter(packet -> packet.inFlight())
                .filter(packetStatus -> packetStatus.setLost())   // Only keep the ones that actually were set to lost
                .collect(Collectors.toList());
        congestionController.discard(inflightPackets);
        ackElicitingInFlight.set(0);
        packetSentLog.clear();
        lossTime = null;
        lastAckElicitingSent = null;
        isClosed = true;
    }

    /**
     * Reset to initial state.
     */
    public synchronized void reset() {
        List<PacketStatus> inflightPackets = packetSentLog.values().stream()
                .filter(packet -> packet.inFlight())
                .filter(packetStatus -> packetStatus.setLost())   // Only keep the ones that actually were set to lost
                .collect(Collectors.toList());
        congestionController.discard(inflightPackets);
        packetSentLog.clear();
        ackElicitingInFlight.set(0);
        lossTime = null;
        lastAckElicitingSent = null;
        largestAcked = -1;
        lost = 0;
    }

    /**
     * Detect lost packets.
     * Intentionally package protected, because it needs to be called by the loss detection timer also.
     */
    void detectLostPackets() {
        if (isClosed) {
            return;
        }

        int lossDelay = (int) (kTimeThreshold * Integer.max(rttEstimater.getSmoothedRtt(), rttEstimater.getLatestRtt()));
        assert(lossDelay > 0);  // Minimum time of kGranularity before packets are deemed lost
        Instant lostSendTime = Instant.now(clock).minusMillis(lossDelay);

        // https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1
        // "A packet is declared lost if it meets all of the following conditions:
        //  o  The packet is unacknowledged, in flight, and was sent prior to an acknowledged packet.
        //  o  The packet was sent kPacketThreshold packets before an acknowledged packet (Section 6.1.1),
        //     or it was sent long enough in the past (Section 6.1.2)."
        // https://www.rfc-editor.org/rfc/rfc9002.html#section-2
        // "Packets are considered in flight when they are ack-eliciting or contain a PADDING frame,
        //  and they have been sent but are not acknowledged, declared lost, or discarded along with old keys."
        Iterator<PacketStatus> iterator = packetSentLog.values().iterator();
        List<PacketStatus> lostPackets = new ArrayList<>();
        Instant earliestSentTime = null;
        while (iterator.hasNext()) {
            PacketStatus p = iterator.next();
            if (p.packet().getPacketNumber() > largestAcked) {
                break;  // No need to check further, because packets are ordered by packet number
            }
            if (p.inFlight()) {
                if (pnTooOld(p) || sentTimeTooLongAgo(p, lostSendTime)) {
                    lostPackets.add(p);
                }
                else {
                    if (earliestSentTime == null || p.timeSent().isBefore(earliestSentTime)) {
                        earliestSentTime = p.timeSent();
                    }
                }
            }
        }

        if (!lostPackets.isEmpty()) {
            declareLost(lostPackets);
        }

        if (earliestSentTime != null && earliestSentTime.isAfter(lostSendTime)) {
            lossTime = earliestSentTime.plusMillis(lossDelay);
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
                .map(p -> p.packet())
                .collect(Collectors.toList());
    }

    // For debugging only
    List<PacketInfo> getInFlight() {
        return packetSentLog.values().stream()
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
                    qLog.emitPacketLostEvent(packetStatus.packet(), Instant.now());
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
