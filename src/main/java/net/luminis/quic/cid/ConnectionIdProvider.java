/*
 * Copyright © 2023 Peter Doornbosch
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
package net.luminis.quic.cid;

import java.net.InetSocketAddress;

/**
 * Provides connection IDs for the current connection.
 */
public interface ConnectionIdProvider {

    /**
     * Returns the initial connection ID. During handshake, this will be _the_ connection ID. After the handshake,
     * new connection IDs might be issued and used by the peer.
     * @return
     */
    byte[] getInitialConnectionId();

    /**
     * Returns the connection ID that this endpoint uses to address the peer.
     * @return
     */
    byte[] getPeerConnectionId(InetSocketAddress clientAddress);

    /**
     * Registers the (initial) client address, so it can be associated with the initial connection ID.
     * @param clientAddress
     */
    void registerClientAddress(InetSocketAddress clientAddress);
}