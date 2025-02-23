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

import tech.kwik.core.packet.QuicPacket;

import java.net.InetSocketAddress;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Simple holder object for a packet (to send) and its packet-lost callback function and client address
 */
public class SendItem {

    protected final static Consumer<QuicPacket> EMPTY_CALLBACK = p -> {};

    private final QuicPacket packet;
    private final Consumer<QuicPacket> packetLostCallback;
    private final InetSocketAddress clientAddress;

    public SendItem(QuicPacket packet, Consumer<QuicPacket> packetLostCallback, InetSocketAddress clientAddress) {
        this.packet = Objects.requireNonNull(packet);
        this.packetLostCallback = Objects.requireNonNull(packetLostCallback);
        this.clientAddress = Objects.requireNonNull(clientAddress);
    }

    public SendItem(QuicPacket packet, InetSocketAddress clientAddress) {
        this.packet = Objects.requireNonNull(packet);
        this.clientAddress = Objects.requireNonNull(clientAddress);
        this.packetLostCallback = EMPTY_CALLBACK;
    }

    public QuicPacket getPacket() {
        return packet;
    }

    public Consumer<QuicPacket> getPacketLostCallback() {
        return packetLostCallback;
    }

    @Override
    public String toString() {
        return packet.toString();
    }

    public InetSocketAddress getClientAddress() {
        return clientAddress;
    }
}
