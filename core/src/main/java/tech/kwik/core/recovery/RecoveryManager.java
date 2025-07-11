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
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.concurrent.DaemonThreadFactory;
import tech.kwik.core.frame.AckFrame;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.impl.FrameReceivedListener;
import tech.kwik.core.impl.HandshakeState;
import tech.kwik.core.impl.HandshakeStateListener;
import tech.kwik.core.impl.Role;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.send.Sender;

import java.time.Clock;
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

/**
 * QUIC Loss Detection is specified in https://www.rfc-editor.org/rfc/rfc9002.html.
 *
 * "QUIC senders use acknowledgments to detect lost packets and a PTO to ensure acknowledgments are received"
 * It uses a single timer, because either there are lost packets to detect, or a probe must be scheduled, never both.
 *
 * <p><h4>Ack based loss detection</h4>
 * When an Ack is received, packets that are sent "long enough" before the largest acked, are deemed lost; for the
 * packets not send "long enough", a timer is set to mark them as lost when "long enough" time has been passed.
 *
 * An example:
 * <pre>{@code
 *         -----------------------time------------------->>
 * sent:   1           2      3        4
 * acked:                                    4
 *         \--- long enough before 4 --/                       => 1 is marked lost immediately
 *                     \--not long enough before 4 --/
 *                                                   |
 *                                                   Set timer at this point in time, as that will be "long enough".
 *                                                   At that time, a new timer will be set for 3, unless acked meanwhile.
 * }</pre></p>
 *
 * <p><h4>Detecting tail loss with probe timeout</h4>
 * When no Acks arrive, no packets will be marked as lost. To trigger the peer to send an ack (so loss detection can do
 * its job again), a probe (ack-eliciting packet) will be sent after the probe timeout. If the situation does not change
 * (i.e. no Acks received), additional probes will be sent, but with an exponentially growing delay.
 *
 * An example:
 * <pre>{@code
 *         -----------------------time------------------->>
 * sent:   1           2      3        4
 * acked:                                    4
 *                            \-- timer set at loss time  --/
 *                                                          |
 *                                                          When the timer fires, there is no new ack received, so
 *                                                          nothing can be marked as lost. A probe is scheduled for
 *                                                          "probe timeout" time after the time 3 was sent:
 *                            \-- timer set at "probe timeout" time after 3 was sent --\
 *                                                                                     |
 *                                                                                     Send probe!
 * }</pre>
 * Note that packet 3 will not be marked as lost as long no ack is received!
 * </p>
 *
 * <p><b>Exceptions</b>
 * Because a server might be blocked by the anti-amplification limit, a client must also send probes when it has no
 * ack eliciting packets in flight, but is not sure whether the peer has validated the client address.
 * </p>
 */
public class RecoveryManager implements FrameReceivedListener<AckFrame>, HandshakeStateListener {

    private enum ProbeType {
        Default,
        SinglePing,
        DoublePing
    }
    private final Clock clock;
    private final Role role;
    private final RttEstimator rttEstimater;
    private final CongestionController congestionController;
    private final LossDetector[] lossDetectors = new LossDetector[PnSpace.values().length];
    private final Sender sender;
    private final Logger log;
    private final ScheduledExecutorService scheduler;
    private final ProbeType probeType;
    private int receiverMaxAckDelay;
    private ScheduledFuture<?> lossDetectionFuture;  // Concurrency: guarded by scheduleLock
    private final Object scheduleLock = new Object();
    private volatile int ptoCount;
    private volatile Instant timerExpiration;
    private volatile HandshakeState handshakeState = HandshakeState.Initial;
    private volatile boolean hasBeenStopped = false;

    public RecoveryManager(Role role, RttEstimator rttEstimater, CongestionController congestionController, Sender sender, Logger logger) {
        this(Clock.systemUTC(), role, rttEstimater, congestionController, sender, logger);
    }

    public RecoveryManager(Clock clock, Role role, RttEstimator rttEstimater, CongestionController congestionController, Sender sender, Logger logger) {
        this.clock = clock;
        this.role = role;
        this.rttEstimater = rttEstimater;
        this.congestionController = congestionController;
        for (PnSpace pnSpace: PnSpace.values()) {
            lossDetectors[pnSpace.ordinal()] = new LossDetector(clock ,this, rttEstimater, congestionController, () -> sender.flush(), logger.getQLog());
        }
        this.sender = sender;
        log = logger;

        scheduler = Executors.newScheduledThreadPool(1, new DaemonThreadFactory("loss-detection"));
        synchronized (scheduleLock) {
            lossDetectionFuture = new NullScheduledFuture();
        }
        probeType = determineProbeType();
    }

    private ProbeType determineProbeType() {
        String propValue = System.getProperty("tech.kwik.core.probe-type");
        if (propValue != null) {
            switch (propValue.toLowerCase()) {
                case "single":
                    log.recovery("Using PingFrame as probe");
                    return ProbeType.SinglePing;
                case "double":
                    log.recovery("Using PaddingFrame as probe");
                    return ProbeType.DoublePing;
            }
        }
        return ProbeType.Default;
    }

    void setLossDetectionTimer() {
        PnSpaceTime earliestLossTime = getEarliestLossTime(LossDetector::getLossTime);
        Instant lossTime = earliestLossTime != null? earliestLossTime.lossTime: null;
        if (lossTime != null) {
            rescheduleLossDetectionTimeout(lossTime);
        }
        else {
            boolean ackElicitingInFlight = ackElicitingInFlight();
            boolean peerAwaitingAddressValidation = peerAwaitingAddressValidation();
            // https://datatracker.ietf.org/doc/html/draft-ietf-quic-recovery-34#section-6.2.2.1
            // "That is, the client MUST set the probe timer if the client has not received an acknowledgment for any of
            //  its Handshake packets and the handshake is not confirmed (...), even if there are no packets in flight."
            if (ackElicitingInFlight || peerAwaitingAddressValidation) {
                PnSpaceTime ptoTimeAndSpace = getPtoTimeAndSpace();
                if (ptoTimeAndSpace == null) {
                    log.recovery("cancelling loss detection timer (no loss time set, no ack eliciting in flight, peer not awaiting address validation (1))");
                    unschedule();
                }
                else {
                    rescheduleLossDetectionTimeout(ptoTimeAndSpace.lossTime);

                    if (log.logRecovery()) {
                        int timeout = (int) Duration.between(clock.instant(), ptoTimeAndSpace.lossTime).toMillis();
                        log.recovery("reschedule loss detection timer for PTO over " + timeout + " millis, "
                                + "based on %s/" + ptoTimeAndSpace.pnSpace + ", because "
                                + (peerAwaitingAddressValidation ? "peerAwaitingAddressValidation " : "")
                                + (ackElicitingInFlight ? "ackElicitingInFlight " : "")
                                + "| RTT:" + rttEstimater.getSmoothedRtt() + "/" + rttEstimater.getRttVar(), ptoTimeAndSpace.lossTime);
                    }
                }
            }
            else {
                log.recovery("cancelling loss detection timer (no loss time set, no ack eliciting in flight, peer not awaiting address validation (2))");
                unschedule();
            }
        }
    }

    /**
     * Determines the current probe timeout.
     * This method is defined in https://www.rfc-editor.org/rfc/rfc9002.html#name-setting-the-loss-detection-.
     * @return a <code>PnSpaceTime</code> object defining the next probe: its time and for which packet number space.
     */
    private PnSpaceTime getPtoTimeAndSpace() {
        int ptoDuration = rttEstimater.getSmoothedRtt() + Integer.max(1, 4 * rttEstimater.getRttVar());
        ptoDuration *= (int) (Math.pow(2, ptoCount));

        // The pseudo code in https://www.rfc-editor.org/rfc/rfc9002.html#name-setting-the-loss-detection- test for
        // ! ackElicitingInFlight() to determine whether peer is awaiting address validation. In a multi-threaded
        // implementation, that solution is subject to all kinds of race conditions, so its better to just check:
        if (peerAwaitingAddressValidation()) {
            if (handshakeState.hasNoHandshakeKeys()) {
                log.recovery("getPtoTimeAndSpace: no ack eliciting in flight and no handshake keys -> probe Initial");
                return new PnSpaceTime(PnSpace.Initial, clock.instant().plusMillis(ptoDuration));
            } else {
                log.recovery("getPtoTimeAndSpace: no ack eliciting in flight but handshake keys -> probe Handshake");
                return new PnSpaceTime(PnSpace.Handshake, clock.instant().plusMillis(ptoDuration));
            }
        }

        // Find earliest pto time
        Instant ptoTime = Instant.MAX;
        PnSpace ptoSpace = null;
        for (PnSpace pnSpace: PnSpace.values()) {
            if (lossDetectors[pnSpace.ordinal()].ackElicitingInFlight()) {
                if (pnSpace == PnSpace.App && handshakeState.isNotConfirmed()) {
                    // https://www.rfc-editor.org/rfc/rfc9002.html#name-setting-the-loss-detection-
                    // "Skip Application Data until handshake confirmed"
                    log.recovery("getPtoTimeAndSpace is skipping level App, because handshake not yet confirmed!");
                    continue;  // Because App is the last, this is effectively a return.
                }
                if (pnSpace == PnSpace.App) {
                    // https://www.rfc-editor.org/rfc/rfc9002.html#name-setting-the-loss-detection-
                    // "Include max_ack_delay and backoff for Application Data"
                    ptoDuration += receiverMaxAckDelay * (int) (Math.pow(2, ptoCount));
                }
                Instant lastAckElicitingSent = lossDetectors[pnSpace.ordinal()].getLastAckElicitingSent();
                if (lastAckElicitingSent != null && lastAckElicitingSent.plusMillis(ptoDuration).isBefore(ptoTime)) {
                    ptoTime = lastAckElicitingSent.plusMillis(ptoDuration);
                    ptoSpace = pnSpace;
                }
            }
        }

        if (ptoSpace != null) {
            return new PnSpaceTime(ptoSpace, ptoTime);
        }
        else {
            return null;
        }
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
        else if (clock.instant().isBefore(expiration) && Duration.between(clock.instant(), expiration).toMillis() > 0) {
            // Might be due to an old task that was cancelled, but unfortunately, it also happens that the scheduler
            // executes tasks much earlier than requested (30 ~ 40 ms). In that case, rescheduling is necessary to avoid
            // losing the loss detection timeout event.
            // To be sure the latest timer expiration is used, use timerExpiration i.s.o. the expiration of this call.
            log.warn(String.format("Loss detection timeout running (at %s) is %s ms too early; rescheduling to %s",
                    clock.instant(), Duration.between(clock.instant(), expiration).toMillis(), timerExpiration));
            rescheduleLossDetectionTimeout(timerExpiration);
        }
        else {
            log.recovery("%s loss detection timeout handler running", clock.instant());
        }

        PnSpaceTime earliestLossTime = getEarliestLossTime(LossDetector::getLossTime);
        Instant lossTime = earliestLossTime != null? earliestLossTime.lossTime: null;
        if (lossTime != null) {
            lossDetectors[earliestLossTime.pnSpace.ordinal()].detectLostPackets();
            reportRecoveryMetrics(false);
            sender.flush();
            setLossDetectionTimer();
        }
        else {
            sendProbe();
            // Calling setLossDetectionTimer here not necessary, because the event of sending the probe will trigger it anyway.
            // And if done here, time of last-ack-eliciting might not be set yet (because packets are sent async), leading to trouble.
        }
    }

    private void reportRecoveryMetrics(boolean includeRttMetrics) {
        long cwnd = congestionController.getWindowSize();
        long bytesInFlight = congestionController.getBytesInFlight();
        if (includeRttMetrics) {
            log.getQLog().emitRecoveryMetrics(cwnd, bytesInFlight, rttEstimater.getSmoothedRtt(), rttEstimater.getRttVar(), rttEstimater.getLatestRtt());
        }
        else {
            log.getQLog ().emitCongestionControlMetrics(cwnd, bytesInFlight);
        }
    }

    private void sendProbe() {
        if (log.logRecovery()) {
            PnSpaceTime earliestLastAckElicitingSentTime = getEarliestLossTime(LossDetector::getLastAckElicitingSent);
            if (earliestLastAckElicitingSentTime != null) {
                log.recovery(String.format("Sending probe %d, because no ack since %%s. Current RTT: %d/%d.", ptoCount, rttEstimater.getSmoothedRtt(), rttEstimater.getRttVar()), earliestLastAckElicitingSentTime.lossTime);
            } else {
                log.recovery(String.format("Sending probe %d. Current RTT: %d/%d.", ptoCount, rttEstimater.getSmoothedRtt(), rttEstimater.getRttVar()));
            }
        }

        ptoCount++;
        int nrOfProbes = ptoCount > 1 ? 2 : 1;

        if (ackElicitingInFlight()) {
            PnSpaceTime ptoTimeAndSpace = getPtoTimeAndSpace();
            if (ptoTimeAndSpace == null) {
                // So, the "ack eliciting in flight" has just been acked; a new timeout will be set, no need to send a probe now
                log.recovery("Refraining from sending probe because received ack meanwhile");
                return;
            }
            sendOneOrTwoAckElicitingPackets(ptoTimeAndSpace.pnSpace, nrOfProbes);
        }
        else {
            // Must be the peer awaiting address validation or race condition
            if (peerAwaitingAddressValidation()) {
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
            else {
                log.recovery("Refraining from sending probe as no ack eliciting in flight and no peer awaiting address validation");
            }
        }
    }

    private void sendOneOrTwoAckElicitingPackets(PnSpace pnSpace, int numberOfPackets) {
        if (probeType == ProbeType.SinglePing) {
            // Send a single PingFrame
            log.recovery("Sending single PingFrame as probe");
            repeatSend(numberOfPackets, () -> sender.sendProbe(List.of(new PingFrame()), pnSpace.relatedEncryptionLevel()));
        }
        else if (probeType == ProbeType.DoublePing) {
            // Send two PingFrames
            log.recovery("Sending two PingFrames as probe");
            repeatSend(numberOfPackets, () -> sender.sendProbe(List.of(new PingFrame(), new PingFrame()), pnSpace.relatedEncryptionLevel()));
        }
        else {
            sendProbesWithData(pnSpace, numberOfPackets);
        }
    }

    private void sendProbesWithData(PnSpace pnSpace, int numberOfPackets) {
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

    void rescheduleLossDetectionTimeout(Instant scheduledTime) {
        try {
            synchronized (scheduleLock) {
                // Cancelling the current future and setting the new must be in a sync'd block to ensure the right future is cancelled
                lossDetectionFuture.cancel(false);
                timerExpiration = scheduledTime;
                long delay = Duration.between(clock.instant(), scheduledTime).toMillis();
                // Delay can be 0 or negative, but that's no problem for ScheduledExecutorService: "Zero and negative delays are also allowed, and are treated as requests for immediate execution."
                lossDetectionFuture = scheduler.schedule(this::runLossDetectionTimeout, delay, TimeUnit.MILLISECONDS);
            }
        }
        catch (RejectedExecutionException taskRejected) {
            // Can happen if has been reset concurrently
            if (!hasBeenStopped) {
                throw taskRejected;
            }
        }
    }

    void resetLossDetectionTimeout() {
        synchronized (scheduleLock) {
            lossDetectionFuture.cancel(false);
            timerExpiration = null;
            lossDetectionFuture = new NullScheduledFuture();
        }
    }

    private void runLossDetectionTimeout() {
        try {
            lossDetectionTimeout();
        } catch (Exception error) {
            log.error("Runtime exception occurred while running loss detection timeout handler", error);
        }
    }

    /**
     * Creates a Runnable to run the lossDetectionTimeout method, but first checks whether it is not running to early.
     * For debugging purposes only: it is / can be used to prove that scheduled tasks sometimes run 30 ~ 40 milliseconds too early.
     * @param scheduledTime
     * @return
     */
    private Runnable createLossDetectionTimeoutRunnerWithTooEarlyDetection(final Instant scheduledTime) {
        return () -> {
            Instant now = clock.instant();
            // Allow for 1 ms difference, as Instant has much more precision than the ScheduledExecutorService
            if (now.plusMillis(1).isBefore(scheduledTime)) {
                log.error(String.format("Task scheduled for %s is running already at %s (%s ms too early)", scheduledTime, now, Duration.between(now, scheduledTime).toMillis()));
            }
            runLossDetectionTimeout();
        };
    }

    void unschedule() {
        lossDetectionFuture.cancel(true);
        timerExpiration = null;
    }

    public void onAckReceived(AckFrame ackFrame, PnSpace pnSpace, Instant timeReceived) {
        if (!hasBeenStopped) {
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
            reportRecoveryMetrics(true);
        }
    }

    public void packetSent(QuicPacket packet, Instant sent, Consumer<QuicPacket> packetLostCallback) {
        if (!hasBeenStopped) {
            if (packet.isInflightPacket()) {
                lossDetectors[packet.getPnSpace().ordinal()].packetSent(packet, sent, packetLostCallback);
                reportRecoveryMetrics(false);
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
        if (!hasBeenStopped) {
            hasBeenStopped = true;
            unschedule();
            scheduler.shutdown();
            for (PnSpace pnSpace: PnSpace.values()) {
                lossDetectors[pnSpace.ordinal()].close();
            }
        }
    }

    public void stopRecovery(PnSpace pnSpace) {
        if (!hasBeenStopped) {
            lossDetectors[pnSpace.ordinal()].close();
            // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-6.2.2
            // "When Initial or Handshake keys are discarded, the PTO and loss detection timers MUST be reset"
            ptoCount = 0;
            setLossDetectionTimer();
        }
    }

    public void reset(PnSpace pnSpace) {
        if (!hasBeenStopped) {
            lossDetectors[pnSpace.ordinal()].reset();
            resetLossDetectionTimeout();
        }
    }
    public long getLost() {
        return Stream.of(lossDetectors).mapToLong(ld -> ld.getLost()).sum();
    }

    @Override
    public void handshakeStateChangedEvent(HandshakeState newState) {
        if (!hasBeenStopped) {
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
    public void received(AckFrame frame, PnSpace pnSpace, Instant timeReceived) {
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
        LocalTime localTimeNow = LocalTime.from(clock.instant().atZone(ZoneId.systemDefault()));
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
