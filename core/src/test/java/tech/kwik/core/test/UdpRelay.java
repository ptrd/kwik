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
package tech.kwik.core.test;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * UDP relay between clients and a server, simulating a router that forwards each flow (address/port tuple) over a
 * path of its own. Every client address gets its own upstream socket, so the server sees a different address for each
 * client flow (as when behind a NAT). A flow can be black-holed (in both directions), which simulates a flow that is
 * hashed onto a network path that stopped delivering packets, while other flows are not affected.
 * The relay binds its sockets to the wildcard address, as the Kwik client does: if it bound them to the loopback address,
 * the OS could hand out the same port to a (wildcard) client socket, and datagrams for that port would then be
 * delivered to the (more specific) relay socket instead of to the client.
 */
public class UdpRelay implements Closeable {

    private final InetSocketAddress server;
    private final DatagramChannel downstream;
    private final Selector selector;
    private final Map<InetSocketAddress, DatagramChannel> upstreams = new ConcurrentHashMap<>();
    private final Map<DatagramChannel, InetSocketAddress> clients = new ConcurrentHashMap<>();
    private final Set<Integer> blackholedPorts = ConcurrentHashMap.newKeySet();
    private final Thread thread;
    private volatile boolean closed;

    public UdpRelay(InetSocketAddress server) throws IOException {
        this.server = server;
        selector = Selector.open();
        downstream = DatagramChannel.open();
        downstream.bind(new InetSocketAddress(0));
        downstream.configureBlocking(false);
        downstream.register(selector, SelectionKey.OP_READ);
        thread = new Thread(this::run, "udp-relay");
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * @return  the address clients should use instead of the server address
     */
    public InetSocketAddress getAddress() throws IOException {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), ((InetSocketAddress) downstream.getLocalAddress()).getPort());
    }

    /**
     * Drops all datagrams of the flow with the given client port from now on, in both directions.
     */
    public void blackhole(int clientPort) {
        blackholedPorts.add(clientPort);
    }

    /**
     * @return  the number of different client flows seen so far
     */
    public int getFlowCount() {
        return upstreams.size();
    }

    @Override
    public void close() {
        closed = true;
        selector.wakeup();
        try {
            thread.join(1000);
            selector.close();
            downstream.close();
            for (DatagramChannel upstream : upstreams.values()) {
                upstream.close();
            }
        }
        catch (IOException | InterruptedException e) {
            // test teardown, nothing left to do
        }
    }

    private void run() {
        ByteBuffer buffer = ByteBuffer.allocate(65535);
        try {
            while (!closed) {
                selector.select(100);
                selector.selectedKeys().clear();
                relayUpstream(buffer);
                for (Map.Entry<DatagramChannel, InetSocketAddress> entry : clients.entrySet()) {
                    relayDownstream(buffer, entry.getKey(), entry.getValue());
                }
            }
        }
        catch (IOException e) {
            if (!closed) {
                throw new IllegalStateException("udp relay failed", e);
            }
        }
    }

    private void relayUpstream(ByteBuffer buffer) throws IOException {
        SocketAddress source;
        while ((source = receive(downstream, buffer)) != null) {
            InetSocketAddress client = (InetSocketAddress) source;
            if (blackholedPorts.contains(client.getPort())) {
                continue;
            }
            DatagramChannel upstream = upstreams.get(client);
            if (upstream == null) {
                upstream = DatagramChannel.open();
                upstream.bind(new InetSocketAddress(0));
                upstream.configureBlocking(false);
                upstream.register(selector, SelectionKey.OP_READ);
                upstreams.put(client, upstream);
                clients.put(upstream, client);
            }
            upstream.send(buffer, server);
        }
    }

    private void relayDownstream(ByteBuffer buffer, DatagramChannel upstream, InetSocketAddress client) throws IOException {
        while (receive(upstream, buffer) != null) {
            if (!blackholedPorts.contains(client.getPort())) {
                downstream.send(buffer, client);
            }
        }
    }

    private static SocketAddress receive(DatagramChannel channel, ByteBuffer buffer) throws IOException {
        buffer.clear();
        SocketAddress source = channel.receive(buffer);
        buffer.flip();
        return source;
    }
}
