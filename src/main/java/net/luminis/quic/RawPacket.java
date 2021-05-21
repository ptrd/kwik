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
package net.luminis.quic;

import java.net.DatagramPacket;
import java.net.InetAddress;
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

    public InetAddress getAddress() {
        return receivedPacket.getAddress();
    }

    public int getPort() {
        return receivedPacket.getPort();
    }
}
