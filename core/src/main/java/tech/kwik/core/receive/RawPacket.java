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
package tech.kwik.core.receive;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Wraps a datagram in order to keep additional data like the time the datagram was received or sent.
 */
public class RawPacket {

    private final DatagramPacket receivedPacket;
    private final Instant timeReceived;
    private final ByteBuffer data;
    private final InetSocketAddress peerAddress;
    private final InetSocketAddress localAddress;

    public RawPacket(DatagramPacket receivedPacket, Instant timeReceived, InetSocketAddress localAddress) {
        this.receivedPacket = receivedPacket;
        this.timeReceived = timeReceived;

        data = ByteBuffer.wrap(receivedPacket.getData(), 0, receivedPacket.getLength());
        this.peerAddress = (InetSocketAddress) receivedPacket.getSocketAddress();
        this.localAddress = localAddress;
    }

    public Instant getTimeReceived() {
        return timeReceived;
    }

    public ByteBuffer getData() {
        return data;
    }

    public int getLength() {
        return data.limit();
    }

    public InetSocketAddress getPeerAddress() {
        return peerAddress;
    }

    public InetSocketAddress getLocalAddress() {
        return localAddress;
    }
}
