/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.send;

import tech.kwik.core.ack.GlobalAckGenerator;
import tech.kwik.core.cc.CongestionControlEventListener;
import tech.kwik.core.cc.CongestionController;
import tech.kwik.core.cc.NewRenoCongestionController;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.crypto.MissingKeysException;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.IdleTimer;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.QLog;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.packet.RetryPacket;
import tech.kwik.core.packet.ShortHeaderPacket;
import tech.kwik.core.recovery.RecoveryManager;
import tech.kwik.core.recovery.RttEstimator;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.lang.Long.max;

/**
 * Sender implementation that queues frames-to-be-sent and assembles packets "just in time" when conditions allow to
 * send a packet.
 *
 * Sending packets is limited by congestion controller, anti-amplification attack limitations and, for stream frames,
 * flow control. However, ack-only packets are not subject to congestion control and probes are not limited by
 * congestion control (but do count); therefore, such packets have priority when other packets are queued because of
 * congestion control limits. Additionally, delayed ack packets don't have to be send immediately, but they have to
 * within a given time frame.
 * To improve packet and frame coalescing, messages should not be sent immediately when there is the expectation that
 * more will follow in due time.
 *
 * So a sender has to wait for any of the following conditions to become true:
 * - received packet completely processed or batch of packets processed and send requests queued
 * - "spontaneous" request queued (e.g. application initiated stream data)
 * - probe request
 * - delayed ack timeout
 * - congestion controller becoming unblocked due to timer-induced loss detection
 */
public class SenderImpl implements Sender, CongestionControlEventListener {

    private final Clock clock;
    private volatile int maxPacketSize;
    private volatile DatagramSocket socket;
    private final InetSocketAddress peerAddress;
    private final QuicConnectionImpl connection;
    private final CongestionController congestionController;
    private final RttEstimator rttEstimater;
    private final Logger log;
    private final QLog qlog;
    private final SendRequestQueue[] sendRequestQueue = new SendRequestQueue[EncryptionLevel.values().length];
    private final GlobalPacketAssembler packetAssembler;
    private final GlobalAckGenerator globalAckGenerator;
    private final RecoveryManager recoveryManager;
    private final IdleTimer idleTimer;
    private final Thread senderThread;
    private final boolean[] discardedSpaces = new boolean[PnSpace.values().length];
    private ConnectionSecrets connectionSecrets;
    private final Object condition = new Object();
    private boolean signalled;

    // Using thread-confinement strategy for concurrency control: only the sender thread created in this class accesses these members
    private volatile boolean running;
    private volatile boolean stopping;
    private volatile boolean stopped;
    private volatile int receiverMaxAckDelay;
    private volatile int datagramsSent;
    private volatile long bytesSent;
    private volatile long dataSent;
    private volatile long packetsSent;
    private AtomicInteger subsequentZeroDelays = new AtomicInteger();
    private volatile boolean lastDelayWasZero = false;
    private volatile int antiAmplificationLimit = -1;
    private volatile Runnable shutdownHook;
    private volatile Instant lastestAckElicitingTime;


    public SenderImpl(VersionHolder version, int maxPacketSize, DatagramSocket socket, InetSocketAddress peerAddress,
                      QuicConnectionImpl connection, String id, Integer initialRtt, Logger log) {
        this(Clock.systemUTC(), version, maxPacketSize, socket, peerAddress, connection, id, initialRtt, log);
    }

    public SenderImpl(Clock clock, VersionHolder version, int maxPacketSize, DatagramSocket socket, InetSocketAddress peerAddress,
                      QuicConnectionImpl connection, String id, Integer initialRtt, Logger log) {
        this.clock = clock;
        this.maxPacketSize = maxPacketSize;
        this.socket = socket;
        this.peerAddress = peerAddress;
        this.connection = connection;
        this.log = log;
        this.qlog = log.getQLog();

        Arrays.stream(EncryptionLevel.values()).forEach(level -> {
            int levelIndex = level.ordinal();
            sendRequestQueue[levelIndex] = new SendRequestQueue(clock, level);
        });

        rttEstimater = (initialRtt == null)? new RttEstimator(log): new RttEstimator(log, initialRtt);
        globalAckGenerator = new GlobalAckGenerator(this, rttEstimater);
        packetAssembler = new GlobalPacketAssembler(version, sendRequestQueue, globalAckGenerator);
        lastestAckElicitingTime = clock.instant();

        congestionController = new NewRenoCongestionController(log, this);

        recoveryManager = new RecoveryManager(connection.getRole(), rttEstimater, congestionController, this, log);
        connection.addHandshakeStateListener(recoveryManager);
        connection.addAckFrameReceivedListener(recoveryManager);

        idleTimer = connection.getIdleTimer();

        senderThread = new Thread(() -> sendLoop(), "sender" + (!id.isBlank()? "-" + id: ""));
        senderThread.setDaemon(true);
    }

    public void start(ConnectionSecrets secrets) {
        connectionSecrets = secrets;
        senderThread.start();
    }

    @Override
    public void send(QuicFrame frame, EncryptionLevel level) {
        sendRequestQueue[level.ordinal()].addRequest(frame, f -> {});
    }

    @Override
    public void send(QuicFrame frame, EncryptionLevel level, Consumer<QuicFrame> frameLostCallback) {
        sendRequestQueue[level.ordinal()].addRequest(frame, frameLostCallback);
    }

    @Override
    public void send(Function<Integer, QuicFrame> frameSupplier, int minimumSize, EncryptionLevel level, Consumer<QuicFrame> lostCallback) {
        sendRequestQueue[level.ordinal()].addRequest(frameSupplier, minimumSize, lostCallback);
    }

    public void sendWithPriority(QuicFrame frame, EncryptionLevel level, Consumer<QuicFrame> lostCallback) {
        sendRequestQueue[level.ordinal()].addPriorityRequest(frame, lostCallback);
        wakeUpSenderLoop();
    }

    public void send(RetryPacket retryPacket) {
        try {
            send(List.of(new SendItem(retryPacket)));
        } catch (IOException e) {
            log.error("Sending packet failed: " + retryPacket);
        }
    }

    @Override
    public void setInitialToken(byte[] token) {
        if (token != null) {
            packetAssembler.setInitialToken(token);
        }
    }

    @Override
    public void sendAck(PnSpace pnSpace, int maxDelay) {
        sendRequestQueue[pnSpace.relatedEncryptionLevel().ordinal()].addAckRequest(maxDelay);
        if (maxDelay > 0) {
            // Now, the sender loop must use a different wait-period, to ensure it wakes up when the delayed ack
            // must be sent.
            // However, given the current implementation of packetProcessed (i.e. it always wakes up the sender loop),
            // it is not necessary to do this with a ...
            // senderThread.interrupt
            // ... because packetProcessed will ensure the new period is computed.
        }
    }

    @Override
    public void sendProbe(EncryptionLevel level) {
        synchronized (discardedSpaces) {
            if (! discardedSpaces[level.relatedPnSpace().ordinal()]) {
                sendRequestQueue[level.ordinal()].addProbeRequest();
                wakeUpSenderLoop();
            }
            else {
                log.warn("Attempt to send probe on discarded space (" + level.relatedPnSpace() + ") => ignoring");
            }
        }
    }

    @Override
    public void sendProbe(List<QuicFrame> frames, EncryptionLevel level) {
        synchronized (discardedSpaces) {
            if (! discardedSpaces[level.relatedPnSpace().ordinal()]) {
                sendRequestQueue[level.ordinal()].addProbeRequest(frames);
                wakeUpSenderLoop();
            }
            else {
                log.warn("Attempt to send probe on discarded space (" + level.relatedPnSpace() + ") => ignoring");
            }
        }
    }

    @Override
    public void packetProcessed(boolean expectingMore) {
        wakeUpSenderLoop();  // If you change this, review this.sendAck()!
    }

    @Override
    public void datagramProcessed(boolean expectingMore) {
        // Nothing, current implementation flushes when packet processed
    }

    @Override
    public void flush() {
        wakeUpSenderLoop();
    }
    
    public void changeAddress(DatagramSocket newSocket) {
        socket = newSocket;
    }

    public void discard(PnSpace space, String reason) {
        synchronized (discardedSpaces) {
            if (!discardedSpaces[space.ordinal()]) {
                packetAssembler.stop(space);
                recoveryManager.stopRecovery(space);
                log.recovery("Discarding pn space " + space + " because " + reason);
                globalAckGenerator.discard(space);
                discardedSpaces[space.ordinal()] = true;
            }
        }
    }

    /**
     * Stop sending packets, but don't shutdown yet, so connection close can be sent.
     */
    public void stop() {
        // Stop sending packets, so discard any packet waiting to be send.
        Arrays.stream(sendRequestQueue).forEach(sendRequestQueue -> sendRequestQueue.clear());

        // No more retransmissions either.
        recoveryManager.stopRecovery();

        stopped = true;
    }

    public void shutdown(Runnable postShutdownAction) {
        assert(stopped);  // Stopped should have be called before.
        // Stop cannot be called here (again), because it would drop ConnectionCloseFrame still waiting to be sent.

        shutdownHook = postShutdownAction;
        stopping = true;
        senderThread.interrupt();
    }

    @Override
    public void bytesInFlightIncreased(long bytesInFlight) {
    }

    @Override
    public void bytesInFlightDecreased(long bytesInFlight) {
        wakeUpSenderLoop();
    }

    private void sendLoop() {
        try {
            running = true;
            while (running) {
                doLoopIteration();
            }
        }
        catch (Throwable fatalError) {
            if (running) {
                log.error("Sender thread aborted with exception", fatalError);
                connection.abortConnection(fatalError);
            }
            else {
                log.warn("Ignoring " + fatalError + " because sender is shutting down.");
            }
        }
        if (shutdownHook != null) {
            shutdownHook.run();
        }
    }

    void doLoopIteration() throws IOException {
        synchronized (condition) {
            try {
                if (! signalled) {
                    long timeout = determineMaximumWaitTime();
                    if (timeout > 0) {
                        condition.wait(timeout);
                    }
                }
                signalled = false;
            }
            catch (InterruptedException e) {
                log.debug("Sender thread is interrupted; probably shutting down? " + running);
            }
        }

        // Determine whether this loop must be ended _before_ composing packets, to avoid race conditions with
        // items being queued just after the packet assembler (for that level) has executed.
        if (stopping) {
            running = false;
        }

        sendIfAny();
    }

    void sendIfAny() throws IOException {
        List<SendItem> items;
        do {
            items = assemblePacket();
            if (!items.isEmpty()) {
                send(items);
            }
        }
        while (!items.isEmpty());
    }

    private void wakeUpSenderLoop() {
        synchronized (condition) {
            signalled = true;
            condition.notify();
        }
    }

    /**
     * Determines the maximum wait (sleep) time before the sender must check again if there is something to send.
     * @return
     */
    long determineMaximumWaitTime() {
        Optional<Instant> nextDelayedSendTime = packetAssembler.nextDelayedSendTime();
        if (nextDelayedSendTime.isPresent()) {
            long delay = max(Duration.between(clock.instant(), nextDelayedSendTime.get()).toMillis(), 0);
            if (delay > 0) {
                subsequentZeroDelays.set(0);
                lastDelayWasZero = false;
                return delay;
            }
            else {
                if (lastDelayWasZero) {
                    int count = subsequentZeroDelays.incrementAndGet();
                    if (count % 20 == 3) {
                        log.error("possible bug: sender is looping in busy wait; got " + count + " iterations");
                    }
                    if (count > 10003) {
                        return 8000;
                    }
                }
                lastDelayWasZero = true;
                // Next time is already in the past, hurry up!
                return 0;
            }
        }

        // No timeout needed, just wait for next action. In theory, infinity should be returned.
        // However, in order to somewhat forgiving for bugs that would lead to deadlocking the sender, use a
        // value that will keep the connection going, but also indicates there is something wrong.
        return 5000;
    }

    void send(List<SendItem> itemsToSend) throws IOException {
        byte[] datagramData = new byte[maxPacketSize];
        ByteBuffer buffer = ByteBuffer.wrap(datagramData);
        try {
            Iterator<SendItem> packetIterator = itemsToSend.iterator();
            while (packetIterator.hasNext()) {
                QuicPacket packet = packetIterator.next().getPacket();
                try {
                    Aead aead = connectionSecrets.getOwnAead(packet.getEncryptionLevel());
                    byte[] packetData = packet.generatePacketBytes(aead);
                    buffer.put(packetData);
                    log.raw("packet sent, pn: " + packet.getPacketNumber(), packetData);
                }
                catch (MissingKeysException e) {
                    if (e.getMissingKeysCause() == MissingKeysException.Cause.DiscardedKeys) {
                        log.warn("Packet not sent because keys are discarded: " + packet);
                        packetIterator.remove();
                    }
                    else {
                        throw new IllegalStateException(e.getMessage());
                    }
                }
            }
        }
        catch (BufferOverflowException bufferOverflow) {
            log.error("Buffer overflow while generating datagram for " + itemsToSend);
            // rethrow
            throw bufferOverflow;
        }
        if (buffer.position() == 0) {
            // Nothing to send
            return;
        }
        
        DatagramPacket datagram = new DatagramPacket(datagramData, buffer.position(), peerAddress.getAddress(), peerAddress.getPort());

        Instant timeSent = clock.instant();
        socket.send(datagram);
        datagramsSent++;
        packetsSent += itemsToSend.size();
        bytesSent += buffer.position();

        itemsToSend.stream()
                .forEach(item -> {
                    recoveryManager.packetSent(item.getPacket(), timeSent, item.getPacketLostCallback());
                    idleTimer.packetSent(item.getPacket(), timeSent);
                });

        List<QuicPacket> packetsSent = itemsToSend.stream().map(item -> item.getPacket()).collect(Collectors.toList());
        if (packetsSent.stream().anyMatch(p -> p.isAckEliciting())) {
            lastestAckElicitingTime = timeSent;
        }
        log.sent(timeSent, packetsSent);
        dataSent += countDataBytes(packetsSent);
        qlog.emitPacketSentEvent(packetsSent, timeSent);
    }

    private List<SendItem> assemblePacket() {
        int remainingCwnd = (int) congestionController.remainingCwnd();
        int currentMaxPacketSize = maxPacketSize;
        if (antiAmplificationLimit >= 0) {
            if (bytesSent < antiAmplificationLimit) {
                if (antiAmplificationLimit - bytesSent < currentMaxPacketSize) {
                    // Note that when anti-amplification limit is limiting the packet size, it is quite likely that no
                    // packets will be sent at all, because initial packets have a minimum size of 1200 bytes.
                    log.warn(String.format("Sending data may be limited by remaining anti-amplification limit of %d bytes", antiAmplificationLimit - bytesSent));
                }
                currentMaxPacketSize = Integer.min(currentMaxPacketSize, (int) (antiAmplificationLimit - bytesSent));
            }
            else {
                log.warn("Cannot send; anti-amplification limit is reached");
                return Collections.emptyList();
            }
        }
        byte[] srcCid = connection.getSourceConnectionId();
        byte[] destCid = connection.getDestinationConnectionId();
        return packetAssembler.assemble(remainingCwnd, currentMaxPacketSize, srcCid, destCid);
    }

    @Override
    public Instant lastAckElicitingSent() {
        return lastestAckElicitingTime;
    }

    private Instant earliest(Instant instant1, Instant instant2) {
        if (instant1 == null) {
            return instant2;
        }
        if (instant2 == null) {
            return instant1;
        }
        if (instant1.isBefore(instant2)) {
            return instant1;
        }
        else {
            return instant2;
        }
    }

    private static long countDataBytes(List<QuicPacket> packets) {
        return packets.stream()
                .filter(p -> p instanceof ShortHeaderPacket)
                .mapToInt(p -> p.getFrames().stream().filter(f -> f instanceof StreamFrame).mapToInt(f -> ((StreamFrame) f).getLength()).sum())
                .sum();
    }

    public SendStatistics getStatistics() {
        return new SendStatistics(datagramsSent, packetsSent, bytesSent, dataSent, recoveryManager.getLost(),
                rttEstimater.getSmoothedRtt(), rttEstimater.getRttVar(), rttEstimater.getLatestRtt());
    }

    public int getPto() {
        return rttEstimater.getSmoothedRtt() + 4 * rttEstimater.getRttVar() + receiverMaxAckDelay;
    }

    public CongestionController getCongestionController() {
        return congestionController;
    }

    public void setReceiverMaxAckDelay(int maxAckDelay) {
        this.receiverMaxAckDelay = maxAckDelay;
        rttEstimater.setMaxAckDelay(maxAckDelay);
        recoveryManager.setReceiverMaxAckDelay(maxAckDelay);
    }

    public GlobalAckGenerator getGlobalAckGenerator() {
        return globalAckGenerator;
    }

    public void setAntiAmplificationLimit(int antiAmplificationLimit) {
        this.antiAmplificationLimit = antiAmplificationLimit;
    }

    public void unsetAntiAmplificationLimit() {
        antiAmplificationLimit = -1;
    }

    public void enableAllLevels() {
        packetAssembler.enableAppLevel();
    }

    public void enableAppLevel() {
        packetAssembler.enableAppLevel();
    }

    public void registerMaxUdpPayloadSize(int maxUdpPayloadSize) {
        if (maxUdpPayloadSize < maxPacketSize) {
            maxPacketSize = maxUdpPayloadSize;
        }
    }

    public void resetRecovery(PnSpace pnSpace) {
        recoveryManager.reset(pnSpace);
    }
}

