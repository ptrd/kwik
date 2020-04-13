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
package net.luminis.quic;

import net.luminis.quic.concurrent.DaemonThreadFactory;
import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.frame.Padding;
import net.luminis.quic.frame.PingFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.packet.ZeroRttPacket;
import net.luminis.quic.recovery.RecoveryManager;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Consumer;
import java.util.stream.Collectors;


public class Sender implements ProbeSender, FrameProcessor {

    private DatagramSocket socket;
    private final int maxPacketSize;
    private final Logger log;
    private final Thread senderThread;
    private InetAddress serverAddress;
    private int port;
    private volatile boolean running;
    private BlockingQueue<WaitingPacket> incomingPacketQueue;
    private final Map<PacketId, PacketAckStatus> packetSentLog;
    private final CongestionController congestionController;
    private ConnectionSecrets connectionSecrets;
    private final RttEstimator rttEstimater;
    private QuicConnectionImpl connection;
    private EncryptionLevel lastReceivedMessageLevel = EncryptionLevel.Initial;
    private AckGenerator[] ackGenerators;
    private final long[] lastPacketNumber = new long[PnSpace.values().length];
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1, new DaemonThreadFactory("sender-scheduler"));
    private RecoveryManager recoveryManager;
    private int receiverMaxAckDelay;
    private volatile long sent;
    private volatile boolean mustSendProbe = false;

    public Sender(DatagramSocket socket, int maxPacketSize, Logger log, InetAddress serverAddress, int port, QuicConnectionImpl connection, Integer initialRtt) {
        this.socket = socket;
        this.maxPacketSize = maxPacketSize;
        this.log = log;
        this.serverAddress = serverAddress;
        this.port = port;
        this.connection = connection;

        senderThread = new Thread(() -> run(), "sender");
        senderThread.setDaemon(true);

        incomingPacketQueue = new LinkedBlockingQueue<>();
        packetSentLog = new ConcurrentHashMap<>();
        congestionController = new NewRenoCongestionController(log);
        if (initialRtt == null) {
            rttEstimater = new RttEstimator(log);
        }
        else {
            rttEstimater = new RttEstimator(log, initialRtt);
        }
        recoveryManager = new RecoveryManager(rttEstimater, congestionController, this, log);
        connection.addHandshakeStateListener(recoveryManager);

        ackGenerators = new AckGenerator[PnSpace.values().length];
        Arrays.setAll(ackGenerators, i -> new AckGenerator());
    }

    public void send(QuicPacket packet, String logMessage, Consumer<QuicPacket> packetLostCallback) {
        log.debug("queing " + packet);
        incomingPacketQueue.add(new WaitingPacket(packet, logMessage, packetLostCallback));
    }

    public void stop() {
        // Stop sending packets, so discard any packet waiting to be send.
        incomingPacketQueue.clear();
        // No more retransmissions either.
        recoveryManager.stopRecovery();
    }

    public int getPto() {
        return rttEstimater.getSmoothedRtt() + 4 * rttEstimater.getRttVar() + receiverMaxAckDelay;
    }

    public void start(ConnectionSecrets secrets) {
        connectionSecrets = secrets;
        senderThread.start();
    }

    private void run() {
        running = true;
        try {
            while (running) {

                try {
                    QuicPacket packet = null;
                    String logMessage = null;
                    EncryptionLevel level = null;
                    long packetNumber = -1;
                    Consumer<QuicPacket> packetLostCallback = p -> {};

                    boolean packetWaiting = incomingPacketQueue.peek() != null;
                    boolean ackWaiting = false;
                    if (!packetWaiting) {
                        level = lastReceivedMessageLevel;
                        AckGenerator ackGenerator = ackGenerators[level.relatedPnSpace().ordinal()];
                        ackWaiting = ackGenerator.hasNewAckToSend();
                    }
                    if (packetWaiting || !ackWaiting) {
                        WaitingPacket queued = incomingPacketQueue.take();
                        packet = queued.packet;
                        level = packet.getEncryptionLevel();
                        logMessage = queued.logMessage;
                        packetLostCallback = queued.packetLostCallback;
                    }

                    Keys keys = connectionSecrets.getClientSecrets(level);// Assuming client role
                    packetNumber = generatePacketNumber(level.relatedPnSpace());
                    byte[] packetData;
                    if (packet == null) {
                        // i.e. ack waiting
                        packetData = new byte[0];
                    }
                    else {
                        packetData = packet.generatePacketBytes(packetNumber, keys);  // TODO: more efficient would be to estimate packet size
                    }

                    boolean hasBeenWaiting = false;
                    if (packet != null) {   // Ack-only is not congestion controller, neither is probe.
                        while (!mustSendProbe && !congestionController.canSend(packetData.length)) {  // mustSendProbe can change while in wait loop
                            log.cc("Congestion controller will not allow sending queued packet " + packet + " (in-flight: " + congestionController.getBytesInFlight() + ", packet length: " + packetData.length + ")");
                            hasBeenWaiting = true;
                            try {
                                congestionController.waitForUpdate();
                            } catch (InterruptedException interrupted) {
                                log.debug("Wait for CC update is interrupted");
                            }
                            log.debug("re-evaluating CC");
                        }

                        if (hasBeenWaiting) {
                            log.debug("Congestion controller now does allow sending the packet.");
                        }
                    }

                    if (mustSendProbe) {
                        mustSendProbe = false;
                        if (!congestionController.canSend(packetData.length)) {
                            log.cc("Exceeding cc window because a probe must be sent.");
                        }
                    }

                    // Ah, here we are, allowed to send a packet. Before doing so, we should check whether there is
                    // an ack frame that should be coalesced with it.

                    if (packet == null || ! (packet instanceof ZeroRttPacket)) {
                        AckGenerator ackGenerator = ackGenerators[level.relatedPnSpace().ordinal()];
                        if (ackGenerator.hasAckToSend()) {
                            AckFrame ackToSend = ackGenerator.generateAckForPacket(packetNumber);
                            if (packet == null) {
                                packet = connection.createPacket(level, ackToSend);
                            } else {
                                packet.addFrame(ackToSend);
                            }
                            packetData = packet.generatePacketBytes(packetNumber, keys);
                        }
                    }

                    DatagramPacket datagram = new DatagramPacket(packetData, packetData.length, serverAddress, port);
                    Instant sent = Instant.now();
                    socket.send(datagram);
                    logSent(packet, sent, packetLostCallback);
                    log.raw("packet sent (" + logMessage + "), pn: " + packet.getPacketNumber(), packetData);
                    log.sent(sent, packet);
                }
                catch (InterruptedException interrupted) {
                    // Someone interrupted, maybe because an Ack has to be sent.
                    log.debug("Sender wait interrupted...");
                }
            }
        }
        catch (IOException ioError) {
            // This is probably fatal.
            log.error("IOException while sending datagrams", ioError);
            connection.abortConnection(ioError);
        }
        catch (Throwable fatal) {
            log.error("Sender thread aborted with exception", fatal);
            connection.abortConnection(fatal);
        }
    }

    public void packetProcessed(EncryptionLevel encryptionLevel) {
        lastReceivedMessageLevel = encryptionLevel;
        // Notify sender loop: might need to send an acknowledge packet.
        senderThread.interrupt();
    }

    private long generatePacketNumber(PnSpace pnSpace) {
        synchronized (lastPacketNumber) {
            return lastPacketNumber[pnSpace.ordinal()]++;
        }
    }

    void shutdown() {
        running = false;
        senderThread.interrupt();
        logStatistics();
        scheduler.shutdownNow();
    }

    private List<QuicPacket> getNonAcknowlegded() {
        return packetSentLog.values().stream().filter(p -> !p.acked).map(o -> o.packet).collect(Collectors.toList());
    }

    public void processPacketReceived(QuicPacket packet) {
        if (packet.canBeAcked()) {
            ackGenerators[packet.getPnSpace().ordinal()].packetReceived(packet);
        }
    }

    /**
     * Process incoming acknowledgement.
     * @param ackFrame
     * @param pnSpace
     * @param timeReceived
     */
    public synchronized void process(QuicFrame ackFrame, PnSpace pnSpace, Instant timeReceived) {
        if (ackFrame instanceof AckFrame) {
            processAck((AckFrame) ackFrame, pnSpace, timeReceived);
        }
        else {
            throw new RuntimeException();  // Would be programming error.
        }
    }

    private void processAck(AckFrame ackFrame, PnSpace pnSpace, Instant timeReceived) {
        ackGenerators[pnSpace.ordinal()].process(ackFrame);

        computeRttSample(ackFrame, pnSpace, timeReceived);

        recoveryManager.onAckReceived(ackFrame, pnSpace);

        ackFrame.getAckedPacketNumbers().stream().forEach(pn -> {
            PacketId id = new PacketId(pnSpace, pn);
            if (packetSentLog.containsKey(id)) {
                Duration ackDuration = Duration.between(Instant.now(), packetSentLog.get(id).timeSent);
                log.debug("Ack duration for " + id + ": " + ackDuration);
                packetSentLog.get(id).acked = true;
            }
        });
    }

    private void computeRttSample(AckFrame ack, PnSpace pnSpace, Instant timeReceived) {
        PacketId largestPnPacket = new PacketId(pnSpace, ack.getLargestAcknowledged());
        PacketAckStatus packetStatus = packetSentLog.get(largestPnPacket);
        if (packetStatus != null) {
            rttEstimater.addSample(timeReceived, packetStatus.timeSent, ack.getAckDelay());
        }
    }

    private void logSent(QuicPacket packet, Instant sendTime, Consumer<QuicPacket> packetLostCallback) {
        recoveryManager.packetSent(packet, sendTime, packetLostCallback);
        packetSentLog.put(packet.getId(), new PacketAckStatus(sendTime, packet));
        sent++;
    }

    void logStatistics() {
        log.stats("Acknowledgement statistics (sent packets):");
        packetSentLog.entrySet().stream().sorted(Map.Entry.comparingByKey()).map(e -> e.getValue()).forEach(e -> {
            log.stats(e.packet.getId() + "\t" + e.status() + "\t" + e.packet);
        });
    }

    public CongestionController getCongestionController() {
        return congestionController;
    }

    public synchronized void setReceiverMaxAckDelay(int receiverMaxAckDelay) {
        this.receiverMaxAckDelay = receiverMaxAckDelay;
        recoveryManager.setReceiverMaxAckDelay(receiverMaxAckDelay);
    }

    public Statistics getStats() {
        Statistics stats = new Statistics();
        stats.setSent(sent);
        stats.setLost(recoveryManager.getLost());
        return stats;
    }

    @Override
    public void sendProbe() {
        QuicPacket packet = connection.createPacket(EncryptionLevel.App, new PingFrame());
        packet.addFrame(new Padding(3));
        mustSendProbe = true;
        send(packet, "probe with ping", f -> {});
        senderThread.interrupt();
    }

    @Override
    public void sendProbe(List<QuicFrame> frames, EncryptionLevel level) {
        QuicPacket packet = connection.createPacket(level, frames.get(0));
        for (int i = 1; i < frames.size(); i++) {
            packet.addFrame(frames.get(i));
        }
        mustSendProbe = true;  // TODO: when two probes are sent in quick succession, the first might reset this flag, so the second might be stopped by the congestion controller
        send(packet, "probe with data", f -> {});
        senderThread.interrupt();
    }

    public void stopRecovery(PnSpace level) {
        recoveryManager.stopRecovery(level);
    }

    public void changeAddress(DatagramSocket newSocket) {
        this.socket = newSocket;
    }


    private static class PacketAckStatus {
        final Instant timeSent;
        final QuicPacket packet;
        public boolean resent;
        boolean acked;

        public PacketAckStatus(Instant sent, QuicPacket packet) {
            this.timeSent = sent;
            this.packet = packet;
        }

        public String status() {
            if (acked) {
                return "Acked";
            }
            else if (resent) {
                return "Resent";
            }
            else {
                return "-";
            }
        }
    }

    private static class WaitingPacket {
        final QuicPacket packet;
        final String logMessage;
        final Consumer<QuicPacket> packetLostCallback;

        public WaitingPacket(QuicPacket packet, String logMessage, Consumer<QuicPacket> packetLostCallback) {
            this.packet = packet;
            this.logMessage = logMessage;
            this.packetLostCallback = packetLostCallback;
        }
    }

}
