package net.luminis.quic;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.stream.Collectors;

public class Sender implements FrameProcessor {

    private final DatagramSocket socket;
    private final int maxPacketSize;
    private final Logger log;
    private final Thread senderThread;
    private InetAddress serverAddress;
    private int port;
    private BlockingQueue<WaitingPacket> incomingPacketQueue;
    private Map<PacketId, PacketAckStatus> packetSentLog;
    private final CongestionController congestionController;


    public Sender(DatagramSocket socket, int maxPacketSize, Logger log, InetAddress serverAddress, int port) {
        this.socket = socket;
        this.maxPacketSize = maxPacketSize;
        this.log = log;
        this.serverAddress = serverAddress;
        this.port = port;

        senderThread = new Thread(() -> run(), "receiver");
        senderThread.setDaemon(true);

        incomingPacketQueue = new LinkedBlockingQueue<>();
        packetSentLog = new HashMap<>();
        congestionController = new CongestionController(log);
    }

    public void send(QuicPacket packet, String logMessage) throws IOException {
        log.debug("queing " + packet);
        incomingPacketQueue.add(new WaitingPacket(packet, logMessage));
    }

    public void start() {
        senderThread.start();
    }

    private void run() {
        try {
            while (!senderThread.isInterrupted()) {

                try {
                    WaitingPacket queued = incomingPacketQueue.take();
                    QuicPacket packet = queued.packet;
                    String logMessage = queued.logMessage;

                    boolean hasBeenWaiting = false;
                    while (! congestionController.canSend(packet)) {
                        log.debug("Congestion controller will not allow sending queued packet " + packet);
                        log.debug("Non-acked packets: " + getNonAcknowlegded());
                        hasBeenWaiting = true;
                        congestionController.waitForUpdate();
                        log.debug("re-evaluating");
                    }

                    if (hasBeenWaiting) {
                        log.debug("But now it does.");
                    }

                    byte[] packetData = packet.getBytes();
                    DatagramPacket datagram = new DatagramPacket(packetData, packetData.length, serverAddress, port);
                    socket.send(datagram);
                    Instant sent = Instant.now();
                    log.raw("packet sent (" + logMessage + "), pn: " + packet.getPacketNumber(), packetData);
                    log.sent(packet);

                    logSent(packet, sent);
                    congestionController.registerInFlight(packet);
                } catch (InterruptedException interrupted) {
                    // Nothing to do, loop will end.
                }
            }
        }
        catch (IOException ioError) {
            // This is probably fatal.
            log.error("IOException while sending datagrams");
        }
    }

    void shutdown() {
        senderThread.interrupt();
        logStatistics();
    }

    private List<QuicPacket> getNonAcknowlegded() {
        return packetSentLog.values().stream().filter(p -> !p.acked).map(o -> o.packet).collect(Collectors.toList());
    }

    /**
     * Process incoming acknowledgement.
     * @param ackFrame
     * @param encryptionLevel
     */
    public synchronized void process(QuicFrame ackFrame, EncryptionLevel encryptionLevel) {
        if (ackFrame instanceof AckFrame) {
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