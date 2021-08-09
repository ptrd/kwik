/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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

import net.luminis.quic.*;
import net.luminis.quic.cc.CongestionController;
import net.luminis.quic.concurrent.DaemonThreadFactory;
import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.frame.Padding;
import net.luminis.quic.frame.PingFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.send.Sender;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RecoveryManager implements FrameProcessor2<AckFrame>, HandshakeStateListener {

    private final Role role;
    private final RttEstimator rttEstimater;
    private final LossDetector[] lossDetectors = new LossDetector[PnSpace.values().length];
    private final Sender sender;
    private final Logger log;
    private final ScheduledExecutorService scheduler;
    private int receiverMaxAckDelay;
    private volatile ScheduledFuture<?> lossDetectionTimer;
    private volatile int ptoCount;
    private volatile Instant timerExpiration;
    private volatile HandshakeState handshakeState = HandshakeState.Initial;
    private volatile boolean hasBeenReset = false;

    public RecoveryManager(FrameProcessorRegistry processorRegistry, Role role, RttEstimator rttEstimater, CongestionController congestionController, Sender sender, Logger logger) {
        this.role = role;
        this.rttEstimater = rttEstimater;
        for (PnSpace pnSpace: PnSpace.values()) {
            lossDetectors[pnSpace.ordinal()] = new LossDetector(this, rttEstimater, congestionController);
        }
        this.sender = sender;
        log = logger;

        processorRegistry.registerProcessor(this);
        scheduler = Executors.newScheduledThreadPool(1, new DaemonThreadFactory("loss-detection"));
        lossDetectionTimer = new NullScheduledFuture();
    }

    void setLossDetectionTimer() {
        PnSpaceTime earliestLossTime = getEarliestLossTime(LossDetector::getLossTime);
        Instant lossTime = earliestLossTime != null? earliestLossTime.lossTime: null;
        if (lossTime != null) {
            lossDetectionTimer.cancel(false);
            int timeout = (int) Duration.between(Instant.now(), lossTime).toMillis();
            lossDetectionTimer = reschedule(() -> lossDetectionTimeout(), timeout);
        }
        else {
            boolean ackElicitingInFlight = ackElicitingInFlight();
            boolean peerAwaitingAddressValidation = peerAwaitingAddressValidation();
            // https://datatracker.ietf.org/doc/html/draft-ietf-quic-recovery-34#section-6.2.2.1
            // "That is, the client MUST set the probe timer if the client has not received an acknowledgment for any of
            //  its Handshake packets and the handshake is not confirmed (...), even if there are no packets in flight."
            if (ackElicitingInFlight || peerAwaitingAddressValidation) {
                PnSpaceTime ptoTimeAndSpace = getPtoTimeAndSpace();
                if (ptoTimeAndSpace.lossTime.equals(Instant.MAX)) {
                    log.recovery("cancelling loss detection timer (no loss time set, no ack eliciting in flight for I/H, peer not awaiting address validation)");
                    unschedule();
                }
                else {
                    int timeout = (int) Duration.between(Instant.now(), ptoTimeAndSpace.lossTime).toMillis();
                    if (timeout < 1) {
                        timeout = 0;
                    }

                    log.recovery("reschedule loss detection timer for PTO over " + timeout + " millis, "
                            + "based on %s/" + ptoTimeAndSpace.pnSpace + ", because "
                            + (peerAwaitingAddressValidation ? "peerAwaitingAddressValidation " : "")
                            + (ackElicitingInFlight ? "ackElicitingInFlight " : "")
                            + "| RTT:" + rttEstimater.getSmoothedRtt() + "/" + rttEstimater.getRttVar(), ptoTimeAndSpace.lossTime);

                    lossDetectionTimer.cancel(false);
                    lossDetectionTimer = reschedule(() -> lossDetectionTimeout(), timeout);
                }
            }
            else {
                log.recovery("cancelling loss detection timer (no loss time set, no ack eliciting in flight, peer not awaiting address validation)");
                unschedule();
            }
        }
    }

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#appendix-A.8
    private PnSpaceTime getPtoTimeAndSpace() {
        int ptoDuration = rttEstimater.getSmoothedRtt() + Integer.max(1, 4 * rttEstimater.getRttVar());
        ptoDuration *= (int) (Math.pow(2, ptoCount));

        if (! ackElicitingInFlight()) {
            // Must be peer awaiting address validation
            if (handshakeState.hasNoHandshakeKeys()) {
                log.info("getPtoTimeAndSpace: no ack eliciting in flight and no handshake keys -> I");
                return new PnSpaceTime(PnSpace.Initial, Instant.now().plusMillis(ptoDuration));
            }
            else {
                log.info("getPtoTimeAndSpace: no ack eliciting in flight and but handshake keys -> H");
                return new PnSpaceTime(PnSpace.Handshake, Instant.now().plusMillis(ptoDuration));
            }
        }

        // Find earliest pto time
        Instant ptoTime = Instant.MAX;
        PnSpace ptoSpace = null;
        for (PnSpace pnSpace: PnSpace.values()) {
            if (lossDetectors[pnSpace.ordinal()].ackElicitingInFlight()) {
                if (pnSpace == PnSpace.App && handshakeState.isNotConfirmed()) {
                    // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#appendix-A.8
                    // Skip Application Data until handshake confirmed
                    log.recovery("getPtoTimeAndSpace is skipping level App, because handshake not yet confirmed!");
                    continue;
                }
                if (pnSpace == PnSpace.App) {
                    ptoDuration += receiverMaxAckDelay * (int) (Math.pow(2, ptoCount));
                }
                Instant lastAckElicitingSent = lossDetectors[pnSpace.ordinal()].getLastAckElicitingSent();  // TODO: dit moet zo nu en dan een NPE geven! (race conditie met ack eliciting in flight / reset
                if (lastAckElicitingSent.plusMillis(ptoDuration).isBefore(ptoTime)) {
                    ptoTime = lastAckElicitingSent.plusMillis(ptoDuration);
                    ptoSpace = pnSpace;
                }
            }
        }
        return new PnSpaceTime(ptoSpace, ptoTime);
    }

    private boolean peerAwaitingAddressValidation() {
        return role == Role.Client && handshakeState.isNotConfirmed() && lossDetectors[PnSpace.Handshake.ordinal()].noAckedReceived();
    }

    private void lossDetectionTimeout() {
        // Because cancelling the ScheduledExecutor task quite often fails, double check whether the timer should expire.
        Instant expiration = timerExpiration;
        if (expiration == null) {
            // Timer was cancelled, but it still fired; ignore
            log.warn("Loss detection timeout: Timer was cancelled.");
            return;
        }
        else if (Instant.now().isBefore(expiration)) {
            // Old timer task was cancelled, but it still fired; just ignore.
            log.warn("Scheduled task running early: " + Duration.between(Instant.now(), expiration) + "(" + expiration + ")");
            // Apparently, sleep is less precise than time measurement; and adding an extra ms is necessary to avoid that after the sleep, it's still too early
            long remainingWaitTime = Duration.between(Instant.now(), expiration).toMillis() + 1;
            if (remainingWaitTime > 0) {  // Time goes on, so remaining time could have become negative in the mean time
                try {
                    Thread.sleep(remainingWaitTime);
                } catch (InterruptedException e) {}
            }
            expiration = timerExpiration;
            if (expiration == null) {
                log.warn("Delayed task: timer expiration is now null, cancelled");
                return;
            }
            else if (Instant.now().isBefore(expiration)) {
                log.warn("Delayed task is now still before timer expiration, probably rescheduled in the meantime; " + Duration.between(Instant.now(), expiration) + "(" + expiration + ")");
                return;
            }
            else {
                log.warn("Delayed task running now");
            }
        }
        else {
            log.recovery("%s loss detection timeout handler running", Instant.now());
        }

        PnSpaceTime earliestLossTime = getEarliestLossTime(LossDetector::getLossTime);
        Instant lossTime = earliestLossTime != null? earliestLossTime.lossTime: null;
        if (lossTime != null) {
            lossDetectors[earliestLossTime.pnSpace.ordinal()].detectLostPackets();
            sender.flush();
            setLossDetectionTimer();
        }
        else {
            sendProbe();
            // Calling setLossDetectionTimer here not necessary, because the event of sending the probe will trigger it anyway.
            // And if done here, time of last-ack-eliciting might not be set yet (because packets are sent async), leading to trouble.
        }
    }

    private void sendProbe() {
        PnSpaceTime earliestLastAckElicitingSentTime = getEarliestLossTime(LossDetector::getLastAckElicitingSent);

        if (earliestLastAckElicitingSentTime != null) {
            log.recovery(String.format("Sending probe %d, because no ack since %%s. Current RTT: %d/%d.", ptoCount, rttEstimater.getSmoothedRtt(), rttEstimater.getRttVar()), earliestLastAckElicitingSentTime.lossTime);
        } else {
            log.recovery(String.format("Sending probe %d. Current RTT: %d/%d.", ptoCount, rttEstimater.getSmoothedRtt(), rttEstimater.getRttVar()));
        }
        ptoCount++;

        int nrOfProbes = ptoCount > 1 ? 2 : 1;

        if (ackElicitingInFlight()) {
            PnSpaceTime ptoTimeAndSpace = getPtoTimeAndSpace();
            sendOneOrTwoAckElicitingPackets(ptoTimeAndSpace.pnSpace, nrOfProbes);
        } else {
            // Must be peer awaiting address validation
            log.recovery("Sending probe because peer awaiting address validation");
            // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-6.2.2.1
            // "When the PTO fires, the client MUST send a Handshake packet if it has Handshake keys, otherwise it
            //  MUST send an Initial packet in a UDP datagram with a payload of at least 1200 bytes."
            if (handshakeState.hasNoHandshakeKeys()) {
                sendOneOrTwoAckElicitingPackets(PnSpace.Initial, 1);
            } else {
                sendOneOrTwoAckElicitingPackets(PnSpace.Handshake, 1);
            }
        }
    }

    private void sendOneOrTwoAckElicitingPackets(PnSpace pnSpace, int numberOfPackets) {
        if (pnSpace == PnSpace.Initial) {
            List<QuicFrame> framesToRetransmit = getFramesToRetransmit(PnSpace.Initial);
            if (!framesToRetransmit.isEmpty()) {
                log.recovery("(Probe is an initial retransmit)");
                repeatSend(numberOfPackets, () ->
                        sender.sendProbe(framesToRetransmit , EncryptionLevel.Initial));
            }
            else {
                // This can happen, when the probe is sent because of peer awaiting address validation
                log.recovery("(Probe is Initial ping, because there is no Initial data to retransmit)");
                repeatSend(numberOfPackets, () ->
                        sender.sendProbe(List.of(new PingFrame(), new Padding(2)), EncryptionLevel.Initial));
            }
        }
        else if (pnSpace == PnSpace.Handshake) {
            // Client role: find ack eliciting handshake packet that is not acked and retransmit its contents.
            List<QuicFrame> framesToRetransmit = getFramesToRetransmit(PnSpace.Handshake);
            if (!framesToRetransmit.isEmpty()) {
                log.recovery("(Probe is a handshake retransmit)");
                repeatSend(numberOfPackets, () ->
                        sender.sendProbe(framesToRetransmit, EncryptionLevel.Handshake));
            }
            else {
                log.recovery("(Probe is a handshake ping)");
                repeatSend(numberOfPackets, () ->
                        sender.sendProbe(List.of(new PingFrame(), new Padding(2)), EncryptionLevel.Handshake));
            }
        }
        else {
            EncryptionLevel probeLevel = pnSpace.relatedEncryptionLevel();
            List<QuicFrame> framesToRetransmit = getFramesToRetransmit(pnSpace);
            if (!framesToRetransmit.isEmpty()) {
                log.recovery(("(Probe is retransmit on level " + probeLevel + ")"));
                repeatSend(numberOfPackets, () ->
                        sender.sendProbe(framesToRetransmit, probeLevel));
            }
            else {
                log.recovery(("(Probe is ping on level " + probeLevel + ")"));
                repeatSend(numberOfPackets, () ->
                        sender.sendProbe(List.of(new PingFrame(), new Padding(2)), probeLevel));
            }
        }
    }

    List<QuicFrame> getFramesToRetransmit(PnSpace pnSpace) {
        List<QuicPacket> unAckedPackets = lossDetectors[pnSpace.ordinal()].unAcked();
        Optional<QuicPacket> ackEliciting = unAckedPackets.stream()
                .filter(p -> p.isAckEliciting())
                // Filter out Ping packets, ie. packets consisting of PingFrame's, padding and AckFrame's only.
                .filter(p -> ! p.getFrames().stream().allMatch(frame -> frame instanceof PingFrame || frame instanceof Padding || frame instanceof AckFrame))
                .findFirst();
        if (ackEliciting.isPresent()) {
            List<QuicFrame> framesToRetransmit = ackEliciting.get().getFrames().stream()
                    .filter(frame -> !(frame instanceof AckFrame))
                    .collect(Collectors.toList());
            return framesToRetransmit;
        }
        else {
            return Collections.emptyList();
        }
    }

    PnSpaceTime getEarliestLossTime(Function<LossDetector, Instant> pnSpaceTimeFunction) {
        PnSpaceTime earliestLossTime = null;
        for (PnSpace pnSpace: PnSpace.values()) {
            Instant pnSpaceLossTime = pnSpaceTimeFunction.apply(lossDetectors[pnSpace.ordinal()]);
            if (pnSpaceLossTime != null) {
                if (earliestLossTime == null) {
                    earliestLossTime = new PnSpaceTime(pnSpace, pnSpaceLossTime);
                } else {
                    if (! earliestLossTime.lossTime.isBefore(pnSpaceLossTime)) {
                        earliestLossTime = new PnSpaceTime(pnSpace, pnSpaceLossTime);
                    }
                }
            }
        }
        return earliestLossTime;
    }

    ScheduledFuture<?> reschedule(Runnable runnable, int timeout) {
        if (! lossDetectionTimer.cancel(false)) {
            log.debug("Cancelling loss detection timer failed");
        }
        timerExpiration = Instant.now().plusMillis(timeout);
        try {
            return scheduler.schedule(() -> {
                try {
                    runnable.run();
                } catch (Exception error) {
                    log.error("Runtime exception occurred while processing scheduled task", error);
                }
            }, timeout, TimeUnit.MILLISECONDS);
        }
        catch (RejectedExecutionException taskRejected) {
            // Can happen if has been reset concurrently
            if (!hasBeenReset) {
                throw taskRejected;
            }
            else {
                return new NullScheduledFuture();
            }
        }
    }

    void unschedule() {
        lossDetectionTimer.cancel(true);
        timerExpiration = null;
    }

    public void onAckReceived(AckFrame ackFrame, PnSpace pnSpace, Instant timeReceived) {
        if (! hasBeenReset) {
            if (ptoCount > 0) {
                // https://datatracker.ietf.org/doc/html/draft-ietf-quic-recovery-34#section-6.2.1
                // "To protect such a server from repeated client probes, the PTO backoff is not reset at a client that
                //  is not yet certain that the server has finished validating the client's address.
                if (!peerAwaitingAddressValidation()) {
                    ptoCount = 0;
                } else {
                    log.recovery("probe count not reset on ack because handshake not yet confirmed");
                }
            }
            lossDetectors[pnSpace.ordinal()].onAckReceived(ackFrame, timeReceived);
        }
    }

    public void packetSent(QuicPacket packet, Instant sent, Consumer<QuicPacket> packetLostCallback) {
        if (! hasBeenReset) {
            if (packet.isInflightPacket()) {
                lossDetectors[packet.getPnSpace().ordinal()].packetSent(packet, sent, packetLostCallback);
                setLossDetectionTimer();
            }
        }
    }

    private boolean ackElicitingInFlight() {
        return Stream.of(lossDetectors).anyMatch(detector -> detector.ackElicitingInFlight());
    }

    public synchronized void setReceiverMaxAckDelay(int receiverMaxAckDelay) {
        this.receiverMaxAckDelay = receiverMaxAckDelay;
    }

    public void stopRecovery() {
        if (! hasBeenReset) {
            hasBeenReset = true;
            unschedule();
            scheduler.shutdown();
            for (PnSpace pnSpace: PnSpace.values()) {
                lossDetectors[pnSpace.ordinal()].reset();
            }
        }
    }

    public void stopRecovery(PnSpace pnSpace) {
        if (! hasBeenReset) {
            lossDetectors[pnSpace.ordinal()].reset();
            // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-6.2.2
            // "When Initial or Handshake keys are discarded, the PTO and loss detection timers MUST be reset"
            ptoCount = 0;
            setLossDetectionTimer();
        }
    }

    public long getLost() {
        return Stream.of(lossDetectors).mapToLong(ld -> ld.getLost()).sum();
    }

    @Override
    public void handshakeStateChangedEvent(HandshakeState newState) {
        if (! hasBeenReset) {
            HandshakeState oldState = handshakeState;
            handshakeState = newState;
            if (newState == HandshakeState.Confirmed && oldState != HandshakeState.Confirmed) {
                log.recovery("State is set to " + newState);
                // https://tools.ietf.org/html/draft-ietf-quic-recovery-30#section-6.2.1
                // "A sender SHOULD restart its PTO timer (...), when the handshake is confirmed (...),"
                setLossDetectionTimer();
            }
        }
    }

    @Override
    public void process(AckFrame frame, PnSpace pnSpace, Instant timeReceived) {
        onAckReceived(frame, pnSpace, timeReceived);
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

    private void repeatSend(int count, Runnable task) {
        for (int i = 0; i < count; i++) {
            task.run();
            try {
                Thread.sleep(1);  // Use a small delay when sending multiple packets
            } catch (InterruptedException e) {
            }
        }
    }

    String timeNow() {
        LocalTime localTimeNow = LocalTime.from(Instant.now().atZone(ZoneId.systemDefault()));
        DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("mm:ss.SSS");
        return timeFormatter.format(localTimeNow);
    }

    static class PnSpaceTime {
        public PnSpace pnSpace;
        public Instant lossTime;

        public PnSpaceTime(PnSpace pnSpace, Instant pnSpaceLossTime) {
            this.pnSpace = pnSpace;
            lossTime = pnSpaceLossTime;
        }

        @Override
        public String toString() {
            return lossTime.toString() + " (in " + pnSpace + ")";
        }
    }
}
