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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.stream.Collectors;

public class Sender implements FrameProcessor {

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
    private QuicConnection connection;
    private EncryptionLevel lastReceivedMessageLevel = EncryptionLevel.Initial;
    private AckGenerator[] ackGenerators;
    private final long[] lastPacketNumber = new long[EncryptionLevel.values().length];


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

        ackGenerators = new AckGenerator[3];
        Arrays.setAll(ackGenerators, i -> new AckGenerator());
    }

    public void send(QuicPacket packet, String logMessage) {
        log.debug("queing " + packet);
        incomingPacketQueue.add(new WaitingPacket(packet, logMessage));
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

                    logSent(packet, sent);
                    congestionController.registerInFlight(packet);
                }
                catch (InterruptedException interrupted) {
                    // Someone interrupted, maybe because an Ack has to be sent.
                }
            }
        }
        catch (IOException ioError) {
            // This is probably fatal.
            log.error("IOException while sending datagrams");
        }
        catch (Throwable fatal) {
            log.error("Sender thread aborted with exception"+ fatal);
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
     */
    public synchronized void process(QuicFrame ackFrame, EncryptionLevel encryptionLevel) {
        if (ackFrame instanceof AckFrame) {
            ackGenerators[encryptionLevel.ordinal()].process(ackFrame, encryptionLevel);

            ((AckFrame) ackFrame).getAckedPacketNumbers().stream().forEach(pn -> {
                PacketId id = new PacketId(encryptionLevel, pn);
                if (packetSentLog.containsKey(id)) {
                    Duration ackDuration = Duration.between(Instant.now(), packetSentLog.get(id).timeSent);
                    log.debug("Ack duration for " + id + ": " + ackDuration);
                    congestionController.registerAcked(packetSentLog.get(id).packet);
                    packetSentLog.get(id).acked = true;
                }
            });
        }
        else {
            throw new RuntimeException();  // Would be programming error.
        }
    }

    private void logSent(QuicPacket packet, Instant sent) {
        packetSentLog.put(packet.getId(), new PacketAckStatus(sent, packet));
    }

    void logStatistics() {
        log.stats("Acknowledgement statistics (sent packets):");
        packetSentLog.entrySet().stream().sorted((e1, e2) -> e1.getKey().compareTo(e2.getKey())).map(e -> e.getValue()).forEach(e -> {
            log.stats(e.packet.getId() + "\t" + (e.acked? "Acked\t": "-    \t") + e.packet);
        });
    }

    public CongestionController getCongestionController() {
        return congestionController;
    }

    private static class PacketAckStatus {
        final Instant timeSent;
        final QuicPacket packet;
        boolean acked;

        public PacketAckStatus(Instant sent, QuicPacket packet) {
            this.timeSent = sent;
            this.packet = packet;
        }
    }

    private static class WaitingPacket {
        final QuicPacket packet;
        final String logMessage;

        public WaitingPacket(QuicPacket packet, String logMessage) {
            this.packet = packet;
            this.logMessage = logMessage;
        }
    }
}
