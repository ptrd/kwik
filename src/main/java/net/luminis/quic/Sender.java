package net.luminis.quic;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class Sender implements FrameProcessor {

    private final DatagramSocket socket;
    private final int maxPacketSize;
    private final Logger log;
    private InetAddress serverAddress;
    private int port;
    private Map<PacketId, PacketAckStatus> packetSentLog;


    public Sender(DatagramSocket socket, int maxPacketSize, Logger log, InetAddress serverAddress, int port) {
        this.socket = socket;
        this.maxPacketSize = maxPacketSize;
        this.log = log;
        this.serverAddress = serverAddress;
        this.port = port;

        packetSentLog = new HashMap<>();
    }

    public synchronized void send(QuicPacket packet, String logMessage) throws IOException {
        byte[] packetData = packet.getBytes();
        DatagramPacket datagram = new DatagramPacket(packetData, packetData.length, serverAddress, port);
        socket.send(datagram);
        Instant sent = Instant.now();
        log.raw("packet sent (" + logMessage + "), pn: " + packet.getPacketNumber(), packetData);
        log.sent(packet);

        logSent(packet, sent);
    }

    public synchronized void process(QuicFrame ackFrame, EncryptionLevel encryptionLevel) {
        if (ackFrame instanceof AckFrame) {
            ((AckFrame) ackFrame).getAckedPacketNumbers().stream().forEach(pn -> {
                PacketId id = new PacketId(encryptionLevel, pn);
                if (packetSentLog.containsKey(id)) {
                    Duration ackDuration = Duration.between(Instant.now(), packetSentLog.get(id).timeSent);
                    log.debug("Ack duration for " + id + ": " + ackDuration);
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

    private static class PacketAckStatus {
        final Instant timeSent;
        final QuicPacket packet;
        boolean acked;

        public PacketAckStatus(Instant sent, QuicPacket packet) {
            this.timeSent = sent;
            this.packet = packet;
        }
    }

}
