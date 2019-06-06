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
    private volatile boolean cryptoInFlight;
    private volatile int failedCryptoRetries;
    private final RttEstimator rttEstimater;
    private QuicConnection connection;
    private EncryptionLevel lastReceivedMessageLevel = EncryptionLevel.Initial;
    private AckGenerator[] ackGenerators;
    private final long[] lastPacketNumber = new long[EncryptionLevel.values().length];
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1, new DaemonThreadFactory("sender-scheduler"));
    private RecoveryManager recoveryManager;


    private int receiverMaxAckDelay;

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
        congestionController = new CongestionController(log);
        rttEstimater = new RttEstimator(log);
        recoveryManager = new RecoveryManager(rttEstimater, this, log);

        ackGenerators = new AckGenerator[3];
        Arrays.setAll(ackGenerators, i -> new AckGenerator());
    }

    public void send(QuicPacket packet, String logMessage, Consumer<QuicPacket> packetLostCallback) {
        log.debug("queing " + packet);
        incomingPacketQueue.add(new WaitingPacket(packet, logMessage, packetLostCallback));
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
                        AckGenerator ackGenerator = ackGenerators[level.ordinal()];
                        ackWaiting = ackGenerator.hasNewAckToSend();
                    }
                    if (packetWaiting || !ackWaiting) {
                        WaitingPacket queued = incomingPacketQueue.take();
                        packet = queued.packet;
                        level = packet.getEncryptionLevel();
                        logMessage = queued.logMessage;
                        packetLostCallback = queued.packetLostCallback;
                    }

                    packetNumber = generatePacketNumber(level);
                    if (packet == null) {
                        packet = connection.createPacket(level, new Padding(10));  // TODO: necessary for min packet length, fix elsewhere
                    }
                    byte[] packetData = packet.generatePacketBytes(packetNumber, connectionSecrets);  // TODO: more efficient would be to estimate packet size

                    boolean hasBeenWaiting = false;
                    while (! congestionController.canSend(packetData.length)) {
                        log.debug("Congestion controller will not allow sending queued packet " + packet);
                        log.debug("Non-acked packets: " + getNonAcknowlegded());
                        hasBeenWaiting = true;
                        congestionController.waitForUpdate();
                        log.debug("re-evaluating");
                    }

                    if (hasBeenWaiting) {
                        log.debug("But now it does.");
                    }

                    // Ah, here we are, allowed to send a packet. Before doing so, we should check whether there is
                    // an ack frame that should be coalesced with it.

                    AckGenerator ackGenerator = ackGenerators[level.ordinal()];
                    if (ackGenerator.hasAckToSend()) {
                        AckFrame ackToSend = ackGenerator.generateAckForPacket(packetNumber);
                        packet.addFrame(ackToSend);
                        packetData = packet.generatePacketBytes(packetNumber, connectionSecrets);
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

    private long generatePacketNumber(EncryptionLevel encryptionLevel) {
        synchronized (lastPacketNumber) {
            return lastPacketNumber[encryptionLevel.ordinal()]++;
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
            ackGenerators[packet.getEncryptionLevel().ordinal()].packetReceived(packet);
        }
    }

    /**
     * Process incoming acknowledgement.
     * @param ackFrame
     * @param encryptionLevel
     * @param timeReceived
     */
    public synchronized void process(QuicFrame ackFrame, EncryptionLevel encryptionLevel, Instant timeReceived) {
        if (ackFrame instanceof AckFrame) {
            processAck((AckFrame) ackFrame, encryptionLevel, timeReceived);
        }
        else {
            throw new RuntimeException();  // Would be programming error.
        }
    }

    private void processAck(AckFrame ackFrame, EncryptionLevel encryptionLevel, Instant timeReceived) {
        ackGenerators[encryptionLevel.ordinal()].process(ackFrame, encryptionLevel);

        computeRttSample(ackFrame, encryptionLevel, timeReceived);

        if (encryptionLevel == EncryptionLevel.App) {
            recoveryManager.onAckReceived(ackFrame, encryptionLevel);
        }

        ackFrame.getAckedPacketNumbers().stream().forEach(pn -> {
            PacketId id = new PacketId(encryptionLevel, pn);
            if (packetSentLog.containsKey(id)) {
                Duration ackDuration = Duration.between(Instant.now(), packetSentLog.get(id).timeSent);
                log.debug("Ack duration for " + id + ": " + ackDuration);
                congestionController.registerAcked(packetSentLog.get(id).packet);
                packetSentLog.get(id).acked = true;
            }
        });

        if (cryptoInFlight) {
            failedCryptoRetries = 0;  // When an ack is received, reset the timeout value for crypto timeouts.
            cryptoInFlight = packetSentLog.values().stream()
                    .filter(p -> !p.acked && !p.resent)
                    .filter(p -> p.packet.isCrypto())
                    .findFirst()
                    .isPresent();
            if (!cryptoInFlight) {
                log.debug("No crypto in flight anymore.");
            }
            else {
                log.debug("Still crypto in flight: " + packetSentLog.values().stream().filter(p -> p.packet.isCrypto())
                        .map(p -> p.packet).collect(Collectors.toList()));
            }
        }
    }

    private void computeRttSample(AckFrame ack, EncryptionLevel encryptionLevel, Instant timeReceived) {
        PacketId largestPnPacket = new PacketId(encryptionLevel, ack.getLargestAcknowledged());
        PacketAckStatus packetStatus = packetSentLog.get(largestPnPacket);
        if (packetStatus != null) {
            rttEstimater.addSample(timeReceived, packetStatus.timeSent, ack.getAckDelay());
        }
    }

    private void logSent(QuicPacket packet, Instant sent, Consumer<QuicPacket> packetLostCallback) {
        if (packet.isCrypto()) {
            if (!cryptoInFlight) {
                log.debug("Start crypto in flight.");
            }
            cryptoInFlight = true;
        }
        packetSentLog.put(packet.getId(), new PacketAckStatus(sent, packet));
        if (packet.getEncryptionLevel() == EncryptionLevel.App) {
            recoveryManager.packetSent(packet, sent, packetLostCallback);
        }
        int rtt = rttEstimater.getSmoothedRtt();
        int timeout = (int) (2 * rtt * Math.pow(2, failedCryptoRetries));
        schedule(() -> checkIsAcked(packet.getId()), timeout, TimeUnit.MILLISECONDS);
    }

    private void checkIsAcked(PacketId id) {
        if (cryptoInFlight) {
            // TODO: all unack'd crypto's should be resent, but for a client there can only be one (i think)
            PacketAckStatus ackStatus = packetSentLog.get(id);
            if (ackStatus.packet.isCrypto() && !ackStatus.acked) {
                if (ackStatus.resent) {
                    throw new IllegalStateException();
                }
                if (! ackStatus.packet.isCrypto()) {
                    throw new IllegalStateException();
                }
                failedCryptoRetries++;
                log.debug("Packet " + id + " not acked; retransmitting");
                retransmit(ackStatus);
            }
        }
    }

    private void retransmit(PacketAckStatus packetStatus) {
        QuicPacket packet = packetStatus.packet;
        packetStatus.resent = true;
        QuicPacket newPacket = packet.copy();
        send(newPacket, "retransmit " + packet.getId(), p -> {});
    }

    void logStatistics() {
        log.stats("Acknowledgement statistics (sent packets):");
        packetSentLog.entrySet().stream().sorted(Map.Entry.comparingByKey()).map(e -> e.getValue()).forEach(e -> {
            log.stats(e.packet.getId() + "\t" + e.status() + "\t" + e.packet);
        });
    }

    void schedule(Runnable runnable, int timeout, TimeUnit timeUnit) {
        scheduler.schedule(() -> {
            try {
                runnable.run();
            }
            catch (Exception error) {
                log.error("Runtime exception occurred while processing scheduled task", error);
            }
        }, timeout, timeUnit);
    }

    public CongestionController getCongestionController() {
        return congestionController;
    }

    public synchronized void setReceiverMaxAckDelay(int receiverMaxAckDelay) {
        this.receiverMaxAckDelay = receiverMaxAckDelay;
        recoveryManager.setReceiverMaxAckDelay(receiverMaxAckDelay);
    }

    @Override
    public void sendProbe() {
        connection.ping();
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
