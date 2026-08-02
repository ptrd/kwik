/*
 * Copyright © 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.core;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;

/**
 * Factory interface for creating datagram sockets.
 * <p>
 * Implementations of this interface can be used to create datagram sockets that are bound to specific networks or
 * interfaces, or that have specific socket options set. This is useful in multi-homed environments where the client
 * may have multiple network interfaces and needs to select the appropriate one for sending datagrams.
 */
public interface DatagramSocketFactory {

    /**
     * Creates a datagram socket that will be used to send datagrams to the given destination.
     * <p>
     * The destination is provided so that an implementation can select the network to bind the socket to when the host
     * is reachable via multiple networks (multi-homed). Implementations that do not need to select a specific network
     * may ignore this parameter.
     *
     * @param destination  the address datagrams sent via this socket will be sent to
     */
    DatagramSocket createSocket(InetAddress destination) throws SocketException;

    /**
     * Creates a datagram socket bound to the given local port, that will be used to send datagrams to the given
     * destination. This is used when the client (re)binds its local address, e.g. for exercising connection migration.
     * <p>
     * The default implementation binds a plain datagram socket to the given port and does not perform any network
     * selection based on the destination; when {@code localPort} is {@code null} it delegates to
     * {@link #createSocket(InetAddress)} so that the destination-based network selection of that method still applies.
     *
     * @param destination  the address datagrams sent via this socket will be sent to
     * @param localPort    the local port to bind to, or {@code null} to let the system pick an ephemeral port
     */
    default DatagramSocket createSocket(InetAddress destination, Integer localPort) throws SocketException {
        if (localPort == null) {
            return createSocket(destination);
        }
        return new DatagramSocket(new InetSocketAddress(localPort));
    }
}
