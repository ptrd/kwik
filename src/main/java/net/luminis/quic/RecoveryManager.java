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
import java.util.concurrent.*;
import java.util.function.Consumer;

public class RecoveryManager {

    private final RttEstimator rttEstimater;
    private final LossDetector lossDetector;
    private final ProbeSender sender;
    private final Logger log;
    private final ScheduledExecutorService scheduler;
    private int receiverMaxAckDelay;
    private volatile ScheduledFuture<?> lossDetectionTimer;
    private volatile int ptoCount;


    RecoveryManager(RttEstimator rttEstimater, ProbeSender sender, Logger logger) {
        this.rttEstimater = rttEstimater;
        lossDetector = new LossDetector(this, rttEstimater);
        this.sender = sender;
        log = logger;

        scheduler = Executors.newScheduledThreadPool(1, new DaemonThreadFactory("loss-detection"));
        lossDetectionTimer = new NullScheduledFuture();
    }

    void setLossDetectionTimer() {
        Instant lossTime = lossDetector.getLossTime();
        if (lossTime != null) {
            lossDetectionTimer.cancel(false);
            int timeout = (int) Duration.between(Instant.now(), lossTime).toMillis();
            lossDetectionTimer = schedule(() -> lossDetectionTimeout(), timeout, TimeUnit.MILLISECONDS);
        }
        else if (ackElicitingInFlight()) {
            int timeout = rttEstimater.getSmoothedRtt() + 4 * rttEstimater.getRttVar() + receiverMaxAckDelay;
            timeout *= (int) (Math.pow(2, ptoCount));
            int pto = timeout;
            lossDetectionTimer.cancel(false);
            lossDetectionTimer = schedule(() -> lossDetectionTimeout(), timeout, TimeUnit.MILLISECONDS);
        }
    }

    private void lossDetectionTimeout() {
        Instant lossTime = lossDetector.getLossTime();
        if (lossTime != null) {
            lossDetector.detectLostPackets();
        }
        else {
            sender.sendProbe();
            ptoCount++;
            System.out.println("PROBE SENT");
        }
        setLossDetectionTimer();
    }

    ScheduledFuture<?> schedule(Runnable runnable, int timeout, TimeUnit timeUnit) {
        return scheduler.schedule(() -> {
            try {
                runnable.run();
            } catch (Exception error) {
                log.error("Runtime exception occurred while processing scheduled task", error);
            }
        }, timeout, timeUnit);
    }

    public void onAckReceived(AckFrame ackFrame, EncryptionLevel encryptionLevel) {
        if (encryptionLevel == EncryptionLevel.App) {
            lossDetector.onAckReceived(ackFrame);
        }
    }

    public void packetSent(QuicPacket packet, Instant sent, Consumer<QuicPacket> packetLostCallback) {
        if (packet.getEncryptionLevel() == EncryptionLevel.App) {
            lossDetector.packetSent(packet, sent, packetLostCallback);
            setLossDetectionTimer();
        }
    }

    private boolean ackElicitingInFlight() {
        return lossDetector.ackElicitingInFlight();
    }

    void shutdown() {
        lossDetectionTimer.cancel(true);
    }

    public synchronized void setReceiverMaxAckDelay(int receiverMaxAckDelay) {
        this.receiverMaxAckDelay = receiverMaxAckDelay;
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

    interface ProbeSender {
        void sendProbe();
    }
}
