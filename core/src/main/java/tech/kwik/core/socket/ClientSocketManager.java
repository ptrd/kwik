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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Controls the socket used by the client to send and receive datagrams.
 * Sockets are registered by local address, and a datagram is always sent from the socket of the address it was
 * assembled for. A socket that is no longer the current or alternate one stays registered (so it can still send and
 * receive) until it is explicitly removed with {@link #removeLocalAddress(InetSocketAddress)}. This way, a datagram
 * assembled for an address just before that address is replaced can still be sent, without the need to make assembling
 * and sending atomic with respect to changing addresses.
 * Methods that change addresses must not be called concurrently with each other; they can be called concurrently with
 * {@link #send(ByteBuffer, InetSocketAddress)}.
 */
public class ClientSocketManager implements SocketManager {

    private final InetSocketAddress serverAddress;
    private MultipleAddressReceiver receiver;
    private final DatagramSocketFactory socketFactory;
    private final Clock clock;
    private final Map<InetSocketAddress, DatagramSocket> socketsByAddress;
    private volatile InetSocketAddress clientAddress;
    private volatile InetSocketAddress alternateClientAddress;

    public ClientSocketManager(InetSocketAddress serverAddress, MultipleAddressReceiver receiver, DatagramSocketFactory datagramSocketFactory) throws SocketException {
        this(serverAddress, receiver, datagramSocketFactory, Clock.systemUTC());
    }

    public ClientSocketManager(InetSocketAddress serverAddress, MultipleAddressReceiver receiver,
                               DatagramSocketFactory datagramSocketFactory, Clock clock) throws SocketException {
        this.serverAddress = serverAddress;
        this.receiver = receiver;
        this.socketFactory = datagramSocketFactory != null? datagramSocketFactory: (address) -> new DatagramSocket();
        this.clock = clock;
        socketsByAddress = new ConcurrentHashMap<>();
        clientAddress = register(socketFactory.createSocket(serverAddress.getAddress()));
    }

    /**
     * Sends the datagram from the socket bound to the given (local) address. When that address is not registered
     * (anymore), or its socket is closed while sending, the datagram is dropped: it is reported as sent, so loss
     * detection will take care of retransmitting its contents.
     */
    @Override
    public Instant send(ByteBuffer data, InetSocketAddress address) throws IOException {
        Instant timeSent = clock.instant();
        DatagramSocket sendSocket = socketsByAddress.get(address);
        if (sendSocket == null) {
            return timeSent;
        }
        DatagramPacket datagram = new DatagramPacket(data.array(), data.limit(), serverAddress.getAddress(), serverAddress.getPort());
        try {
            sendSocket.send(datagram);
        }
        catch (SocketException socketException) {
            if (!sendSocket.isClosed() || socketsByAddress.containsKey(address)) {
                throw socketException;
            }
            // Socket was removed (and closed) while sending, so dropping the datagram is ok.
        }
        return timeSent;
    }

    @Override
    public void close() {
        socketsByAddress.values().forEach(DatagramSocket::close);
    }

    @Override
    public InetSocketAddress getClientAddress() {
        return clientAddress;
    }

    public InetSocketAddress getLocalSocketAddress() {
        return (InetSocketAddress) getSocket().getLocalSocketAddress();
    }

    /**
     * Makes the alternate address (when the given port matches it) or a new address the current one. The previous
     * address stays registered until it is removed with {@link #removeLocalAddress(InetSocketAddress)}.
     * @param port  the local port to use, or null for an ephemeral port
     * @return  the new current address
     */
    public InetSocketAddress changeLocalAddress(Integer port) throws SocketException {
        InetSocketAddress alternate = alternateClientAddress;
        if (port == null || alternate == null || alternate.getPort() != port) {
            clientAddress = register(socketFactory.createSocket(serverAddress.getAddress(), port));
        }
        else {
            clientAddress = alternate;
            alternateClientAddress = null;
        }
        return clientAddress;
    }

    public DatagramSocket getSocket() {
        return socketsByAddress.get(clientAddress);
    }

    public InetSocketAddress addLocalAddress(Integer port) throws SocketException {
        alternateClientAddress = register(socketFactory.createSocket(serverAddress.getAddress(), port));
        return alternateClientAddress;
    }

    public InetSocketAddress getAlternateClientAddress() {
        return alternateClientAddress;
    }

    /**
     * Stops using the given local address, closing its socket. The current address cannot be removed.
     */
    public void removeLocalAddress(InetSocketAddress address) {
        if (address.equals(clientAddress)) {
            throw new IllegalArgumentException("Cannot remove current address");
        }
        if (address.equals(alternateClientAddress)) {
            alternateClientAddress = null;
        }
        DatagramSocket socketToRemove = socketsByAddress.remove(address);
        if (socketToRemove != null) {
            receiver.removeSocket(socketToRemove);
        }
    }

    private InetSocketAddress register(DatagramSocket socket) {
        InetSocketAddress address = new InetSocketAddress(socket.getInetAddress(), socket.getLocalPort());
        // Register before the address is published, so a datagram assembled for it can always be sent.
        socketsByAddress.put(address, socket);
        receiver.addSocket(socket);
        return address;
    }
}
