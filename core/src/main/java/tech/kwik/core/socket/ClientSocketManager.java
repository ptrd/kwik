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

import tech.kwik.core.DatagramSocketFactory;
import tech.kwik.core.receive.MultipleAddressReceiver;

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
    private MultipleAddressReceiver receiver;
    private final DatagramSocketFactory socketFactory;
    private final Clock clock;
    private volatile DatagramSocket socket;
    private volatile DatagramSocket alternateSocket;
    private InetSocketAddress clientAddress;
    private InetSocketAddress alternateClientAddress;

    public ClientSocketManager(InetSocketAddress serverAddress, MultipleAddressReceiver receiver, DatagramSocketFactory datagramSocketFactory) throws SocketException {
        this(serverAddress, receiver, datagramSocketFactory, Clock.systemUTC());
    }

    public ClientSocketManager(InetSocketAddress serverAddress, MultipleAddressReceiver receiver,
                               DatagramSocketFactory datagramSocketFactory, Clock clock) throws SocketException {
        this.serverAddress = serverAddress;
        this.receiver = receiver;
        this.socketFactory = datagramSocketFactory != null? datagramSocketFactory: (address) -> new DatagramSocket();
        this.clock = clock;
        this.socket = this.socketFactory.createSocket(serverAddress.getAddress());
        clientAddress = new InetSocketAddress(socket.getInetAddress(), socket.getLocalPort());

        receiver.addSocket(socket);
    }

    @Override
    public Instant send(ByteBuffer data, InetSocketAddress address) throws IOException {
        DatagramSocket sendSocket;
        if (address.equals(clientAddress)) {
            sendSocket = socket;
        }
        else if (address.equals(alternateClientAddress)) {
            sendSocket = alternateSocket;
        }
        else {
            throw new IllegalStateException("client address is not registered");
        }
        DatagramPacket datagram = new DatagramPacket(data.array(), data.limit(), serverAddress.getAddress(), serverAddress.getPort());
        Instant timeSent = clock.instant();
        sendSocket.send(datagram);
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

    public InetSocketAddress changeClientPort(Integer port) throws SocketException {
        DatagramSocket newSocket;
        if (port != null) {
            newSocket = new DatagramSocket(new InetSocketAddress(port));
        }
        else {
            newSocket = new DatagramSocket();
        }
        receiver.addSocket(newSocket);
        receiver.removeSocket(socket);
        socket = newSocket;
        clientAddress = new InetSocketAddress(socket.getInetAddress(), socket.getLocalPort());
        return clientAddress;
    }

    public DatagramSocket getSocket() {
        return socket;
    }

    public InetSocketAddress bindNewLocalAddress() throws SocketException {
        alternateSocket = new DatagramSocket();
        alternateClientAddress = new InetSocketAddress(alternateSocket.getInetAddress(), alternateSocket.getLocalPort());
        receiver.addSocket(alternateSocket);
        return alternateClientAddress;
    }
}
