/*
 * Copyright © 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.socket;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Instant;

/**
 * Controls how the (common) server socket is used to send datagrams to the client associated with one particular QUIC connection.
 */
public class ServerConnectionSocketManager implements SocketManager {

    private final DatagramSocket serverSocket;
    private volatile InetSocketAddress clientAddress;
    private final Clock clock;

    public ServerConnectionSocketManager(DatagramSocket serverSocket, InetSocketAddress initialClientAddress) {
        this.serverSocket = serverSocket;
        this.clientAddress = initialClientAddress;
        this.clock = Clock.systemUTC();
    }

    public Instant send(ByteBuffer data) throws IOException {
        return send(data, clientAddress);
    }

    @Override
    public Instant send(ByteBuffer data, InetSocketAddress clientAddress) throws IOException {
        DatagramPacket datagram = new DatagramPacket(data.array(), data.limit(), clientAddress.getAddress(), clientAddress.getPort());
        Instant timeSent = clock.instant();
        serverSocket.send(datagram);
        return timeSent;
    }

    @Override
    public void close() {
        // Note that the serverSocket must not be closed here, as it is used for all server connections ;-)
    }

    @Override
    public InetSocketAddress getClientAddress() {
        return clientAddress;
    }

    public void changeClientAddress(InetSocketAddress clientAddress) {
        this.clientAddress = clientAddress;
    }
}
