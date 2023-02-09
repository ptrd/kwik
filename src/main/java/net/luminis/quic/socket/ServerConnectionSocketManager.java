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
package net.luminis.quic.socket;

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
    private final InetSocketAddress initialClientAddress;
    private final Clock clock;

    public ServerConnectionSocketManager(DatagramSocket serverSocket, InetSocketAddress initialClientAddress) {
        this.serverSocket = serverSocket;
        this.initialClientAddress = initialClientAddress;
        this.clock = Clock.systemUTC();
    }

    @Override
    public Instant send(ByteBuffer data) throws IOException {
        DatagramPacket datagram = new DatagramPacket(data.array(), data.limit(), initialClientAddress.getAddress(), initialClientAddress.getPort());
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
        return initialClientAddress;
    }
}
