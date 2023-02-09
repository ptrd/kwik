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
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Instant;


public class ClientSocketManager implements SocketManager {

    private final InetSocketAddress serverAddress;
    private final Clock clock;
    private volatile DatagramSocket socket;
    private InetSocketAddress clientAddress;

    public ClientSocketManager(InetSocketAddress serverAddress) throws SocketException {
        this(serverAddress, Clock.systemUTC());
    }

    public ClientSocketManager(InetSocketAddress serverAddress, Clock clock) throws SocketException {
        this.serverAddress = serverAddress;
        this.clock = clock;
        this.socket = new DatagramSocket();
        clientAddress = new InetSocketAddress(socket.getInetAddress(), socket.getLocalPort());
    }

    @Override
    public Instant send(ByteBuffer data) throws IOException {
        DatagramPacket datagram = new DatagramPacket(data.array(), data.limit(), serverAddress.getAddress(), serverAddress.getPort());
        Instant timeSent = clock.instant();
        socket.send(datagram);
        return timeSent;
    }

    @Override
    public void close() {
        socket.close();
    }

    @Override
    public InetSocketAddress getClientAddress() {
        return clientAddress;
    }

    public InetSocketAddress getLocalSocketAddress() {
        return (InetSocketAddress) socket.getLocalSocketAddress();
    }

    public void changeClientAddress(DatagramSocket newSocket) {
        socket = newSocket;
    }

    public DatagramSocket getSocket() {
        return socket;
    }
}
