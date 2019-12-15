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
import net.luminis.quic.frame.Padding;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;

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

    private final DatagramSocket socket;
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
    private QuicConnection connection;
    private EncryptionLevel lastReceivedMessageLevel = EncryptionLevel.Initial;
    private AckGenerator[] ackGenerators;
    private final long[] lastPacketNumber = new long[PnSpace.values().length];
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1, new DaemonThreadFactory("sender-scheduler"));
    private RecoveryManager recoveryManager;
    private int receiverMaxAckDelay;
    private volatile long sent;


    public Sender(DatagramSocket socket, int maxPacketSize, Logger log, InetAddress serverAddress, int port, QuicConnection connection) {
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
        rttEstimater = new RttEstimator(log);
        recoveryManager = new RecoveryManager(rttEstimater, congestionController, this, log);

        ackGenerators = new AckGenerator[PnSpace.values().length];
        Arrays.setAll(ackGenerators, i -> new AckGenerator());
    }

    public void send(QuicPacket packet, String logMessage, Consumer<QuicPacket> packetLostCallback) {
        log.debug("queing " + packet);
        incomingPacketQueue.add(new WaitingPacket(packet, logMessage, packetLostCallback));
    }

    public void sendProbe(List<QuicFrame> frames, EncryptionLevel level) {
        QuicPacket packet = connection.createPacket(level, frames.get(0));
        for (int i = 1; i < frames.size(); i++) {
            packet.addFrame(frames.get(i));
        }
        connection.send(packet, "probe with data");
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

                    packetNumber = generatePacketNumber(level.relatedPnSpace());
                    if (packet == null) {
                        packet = connection.createPacket(level, new Padding(10));  // TODO: necessary for min packet length, fix elsewhere
                    }

                    Keys keys = connectionSecrets.getClientSecrets(packet.getEncryptionLevel());// Assuming client role
                    byte[] packetData = packet.generatePacketBytes(packetNumber, keys);  // TODO: more efficient would be to estimate packet size

                    boolean hasBeenWaiting = false;
                    while (! congestionController.canSend(packetData.length)) {
                        log.debug("Congestion controller will not allow sending queued packet " + packet);
                        log.debug("Non-acked packets: " + getNonAcknowlegded());
                        hasBeenWaiting = true;
                        try {
                            congestionController.waitForUpdate();
                        }
                        catch (InterruptedException interrupted) {
                            log.debug("Wait for CC update is interrupted");
                        }
                        log.debug("re-evaluating");
                    }

                    if (hasBeenWaiting) {
                        log.debug("But now it does.");
                    }

                    // Ah, here we are, allowed to send a packet. Before doing so, we should check whether there is
                    // an ack frame that should be coalesced with it.

                    AckGenerator ackGenerator = ackGenerators[level.relatedPnSpace().ordinal()];
                    if (ackGenerator.hasAckToSend()) {
                        AckFrame ackToSend = ackGenerator.generateAckForPacket(packetNumber);
                        packet.addFrame(ackToSend);
                        packetData = packet.generatePacketBytes(packetNumber, keys);
                    }

                    DatagramPacket datagram = new DatagramPacket(packetData, packetData.length, serverAddress, port);
                    Instant sent = Instant.now();
                    socket.send(datagram);
                    log.raw("packet sent (" + logMessage + "), pn: " + packet.getPacketNumber(), packetData);
                    log.sent(sent, packet);

                    logSent(packet, sent, packetLostCallback);
                    congestionController.registerInFlight(packet);
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
        sent++;
        packetSentLog.put(packet.getId(), new PacketAckStatus(sendTime, packet));
        recoveryManager.packetSent(packet, sendTime, packetLostCallback);
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
        connection.ping();
    }

    public void stopRecovery(PnSpace level) {
        recoveryManager.stopRecovery(level);
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
