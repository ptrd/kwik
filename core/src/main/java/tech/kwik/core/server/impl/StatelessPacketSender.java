/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.core.server.impl;

import tech.kwik.core.crypto.Aead;
import tech.kwik.core.packet.QuicPacket;

import java.net.InetSocketAddress;

/**
 * Sends packets that are not sent as part of an established connection (and thus not via a connection's sender),
 * e.g. Retry packets.
 */
@FunctionalInterface
public interface StatelessPacketSender {

    /**
     * Sends the given packet to the given client address.
     * @param clientAddress  the address to send the packet to
     * @param packet  the packet to send
     * @param aead  the aead to use for protecting the packet, or null for packets that are not protected
     */
    void send(InetSocketAddress clientAddress, QuicPacket packet, Aead aead);
}
