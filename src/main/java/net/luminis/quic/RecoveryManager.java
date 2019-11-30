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

import net.luminis.quic.concurrent.DaemonThreadFactory;
import net.luminis.quic.frame.AckFrame;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.stream.Stream;

public class RecoveryManager {

    private final RttEstimator rttEstimater;
    private final LossDetector[] lossDetectors = new LossDetector[EncryptionLevel.values().length];
    private final ProbeSender sender;
    private final Logger log;
    private final ScheduledExecutorService scheduler;
    private int receiverMaxAckDelay;
    private volatile ScheduledFuture<?> lossDetectionTimer;
    private volatile int ptoCount;
    private volatile Instant lastAckElicitingSent;
    private volatile Instant timerExpiration;


    RecoveryManager(RttEstimator rttEstimater, CongestionController congestionController, ProbeSender sender, Logger logger) {
        this.rttEstimater = rttEstimater;
        for (EncryptionLevel pnSpace: EncryptionLevel.values()) {
            lossDetectors[pnSpace.ordinal()] = new LossDetector(this, rttEstimater, congestionController);
        }
        this.sender = sender;
        log = logger;

        scheduler = Executors.newScheduledThreadPool(1, new DaemonThreadFactory("loss-detection"));
        lossDetectionTimer = new NullScheduledFuture();
    }

    void setLossDetectionTimer() {
        PnSpaceLossTime earliestLossTime = getEarliestLossTime();
        Instant lossTime = earliestLossTime != null? earliestLossTime.lossTime: null;
        if (lossTime != null) {
            lossDetectionTimer.cancel(false);
            int timeout = (int) Duration.between(Instant.now(), lossTime).toMillis();
            lossDetectionTimer = reschedule(() -> lossDetectionTimeout(), timeout);
        }
        else if (ackElicitingInFlight()) {
            int ptoTimeout = rttEstimater.getSmoothedRtt() + 4 * rttEstimater.getRttVar() + receiverMaxAckDelay;
            ptoTimeout *= (int) (Math.pow(2, ptoCount));
            int timeout = (int) Duration.between(Instant.now(), lastAckElicitingSent.plusMillis(ptoTimeout)).toMillis();
            lossDetectionTimer.cancel(false);
            lossDetectionTimer = reschedule(() -> lossDetectionTimeout(), timeout);
        }
        else {
            unschedule();
        }
    }

    private void lossDetectionTimeout() {
        // Because cancelling the ScheduledExecutor task quite often fails, double check whether the timer should expire.
        if (timerExpiration == null) {
            // Timer was cancelled, but it still fired; ignore
            return;
        }
        else if (Instant.now().isBefore(timerExpiration)) {
            // Old timer task was cancelled, but it still fired; just ignore.
            return;
        }

        PnSpaceLossTime earliestLossTime = getEarliestLossTime();
        Instant lossTime = earliestLossTime != null? earliestLossTime.lossTime: null;
        if (lossTime != null) {
            lossDetectors[earliestLossTime.pnSpace.ordinal()].detectLostPackets();
        }
        else {
            sendProbe();
            ptoCount++;
        }
        setLossDetectionTimer();
    }

    private void sendProbe() {
        log.recovery(String.format("Sending probe %d, because no ack since %s. Current RTT: %d/%d.", ptoCount, lastAckElicitingSent.toString(), rttEstimater.getSmoothedRtt(), rttEstimater.getRttVar()));
        List<QuicPacket> unAckedInitialPackets = lossDetectors[EncryptionLevel.Initial.ordinal()].unAcked();
        if (! unAckedInitialPackets.isEmpty()) {
            // Client role: there can only be one (unique) initial, as the client sends only one Initial packet.
            // All frames need to be resent, because Initial packet wil contain padding.
            sender.sendProbe(unAckedInitialPackets.get(0).getFrames(), EncryptionLevel.Initial);
        }
        else {
            List<QuicPacket> handshakes = lossDetectors[EncryptionLevel.Handshake.ordinal()].unAcked();

            if (! handshakes.isEmpty()) {
                // TODO
            }
            else {
                sender.sendProbe();
            }
        }
    }

    PnSpaceLossTime getEarliestLossTime() {
        PnSpaceLossTime earliestLossTime = null;
        for (EncryptionLevel pnSpace: EncryptionLevel.values()) {
            Instant pnSpaceLossTime = lossDetectors[pnSpace.ordinal()].getLossTime();
            if (pnSpaceLossTime != null) {
                if (earliestLossTime == null) {
                    earliestLossTime = new PnSpaceLossTime(pnSpace, pnSpaceLossTime);
                } else {
                    if (! earliestLossTime.lossTime.isBefore(pnSpaceLossTime)) {
                        earliestLossTime = new PnSpaceLossTime(pnSpace, pnSpaceLossTime);
                    }
                }
            }
        }
        return earliestLossTime;
    }

    ScheduledFuture<?> reschedule(Runnable runnable, int timeout) {
        lossDetectionTimer.cancel(false);
        timerExpiration = Instant.now().plusMillis(timeout);
        return scheduler.schedule(() -> {
            try {
                runnable.run();
            } catch (Exception error) {
                log.error("Runtime exception occurred while processing scheduled task", error);
            }
        }, timeout, TimeUnit.MILLISECONDS);
    }

    void unschedule() {
        lossDetectionTimer.cancel(false);
        timerExpiration = null;
    }

    public void onAckReceived(AckFrame ackFrame, EncryptionLevel encryptionLevel) {
        ptoCount = 0;
        lossDetectors[encryptionLevel.ordinal()].onAckReceived(ackFrame);
    }

    public void packetSent(QuicPacket packet, Instant sent, Consumer<QuicPacket> packetLostCallback) {
        if (packet.isAckEliciting()) {
            lastAckElicitingSent = sent;
        }

        lossDetectors[packet.getEncryptionLevel().ordinal()].packetSent(packet, sent, packetLostCallback);
        setLossDetectionTimer();  // TODO: why call this for ack-only packets?
    }

    private boolean ackElicitingInFlight() {
        return Stream.of(lossDetectors).anyMatch(detector -> detector.ackElicitingInFlight());
    }

    void shutdown() {
        lossDetectionTimer.cancel(true);
    }

    public synchronized void setReceiverMaxAckDelay(int receiverMaxAckDelay) {
        this.receiverMaxAckDelay = receiverMaxAckDelay;
    }

    public void stopRecovery() {
        for (EncryptionLevel level: EncryptionLevel.values()) {
            stopRecovery(level);
        }
        lossDetectionTimer.cancel(true);
    }

    public void stopRecovery(EncryptionLevel level) {
        lossDetectors[level.ordinal()].reset();
    }

    public long getLost() {
        return Stream.of(lossDetectors).mapToLong(ld -> ld.getLost()).sum();
    }

    private static class NullScheduledFuture implements ScheduledFuture<Void> {
        @Override
        public int compareTo(Delayed o) {
            return 0;
        }

        @Override
        public long getDelay(TimeUnit unit) {
            return 0;
        }

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            return false;
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        @Override
        public boolean isDone() {
            return false;
        }

        @Override
        public Void get() throws InterruptedException, ExecutionException {
            return null;
        }

        @Override
        public Void get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            return null;
        }
    }

    String timeNow() {
        LocalTime localTimeNow = LocalTime.from(Instant.now().atZone(ZoneId.systemDefault()));
        DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("mm:ss.SSS");
        return timeFormatter.format(localTimeNow);
    }

    static class PnSpaceLossTime {
        public EncryptionLevel pnSpace;
        public Instant lossTime;

        public PnSpaceLossTime(EncryptionLevel pnSpace, Instant pnSpaceLossTime) {
            this.pnSpace = pnSpace;
            lossTime = pnSpaceLossTime;
        }
    }
}
