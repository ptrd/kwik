/*
 * Copyright © 2024 Peter Doornbosch
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
package net.luminis.quic.server.impl;

import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.DatagramFilter;
import net.luminis.quic.packet.PacketMetaData;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;

public class ServerConnectionWrapper implements ServerConnectionProxy {

    private final ServerConnectionProxy connection;
    private final Logger log;
    private final DatagramFilter filter;

    public ServerConnectionWrapper(ServerConnectionProxy connection, Logger log, DatagramFilter filter) {
        this.connection = connection;
        this.log = log;
        this.filter = filter;
    }

    @Override
    public byte[] getOriginalDestinationConnectionId() {
        return connection.getOriginalDestinationConnectionId();
    }

    @Override
    public void parsePackets(int datagramNumber, Instant timeReceived, ByteBuffer data, InetSocketAddress sourceAddress) {
        filter.processDatagram(data, new PacketMetaData(timeReceived, sourceAddress, datagramNumber));
    }

    @Override
    public boolean isClosed() {
        return connection.isClosed();
    }

    @Override
    public void closeConnection() {
        connection.closeConnection();
    }

    @Override
    public void dispose() {
        connection.dispose();
    }
}
