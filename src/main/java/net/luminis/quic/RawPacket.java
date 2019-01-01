package net.luminis.quic;

import java.net.DatagramPacket;
import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Wraps a datagram in order to keep additional data like the time the datagram was received or sent.
 */
public class RawPacket {

    private final DatagramPacket receivedPacket;
    private final Instant timeReceived;
    private final int number;
    private final ByteBuffer data;

    public RawPacket(DatagramPacket receivedPacket, Instant timeReceived, int number) {
        this.receivedPacket = receivedPacket;
        this.timeReceived = timeReceived;
        this.number = number;

        data = ByteBuffer.wrap(receivedPacket.getData(), 0, receivedPacket.getLength());
    }

    public Instant getTimeReceived() {
        return timeReceived;
    }

    public int getNumber() {
        return number;
    }

    public ByteBuffer getData() {
        return data;
    }

    public int getLength() {
        return data.limit();
    }
}
