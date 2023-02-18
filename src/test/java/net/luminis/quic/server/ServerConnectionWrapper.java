/*
 * Copyright © 2022, 2023 Peter Doornbosch
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
package net.luminis.quic.server;

import net.luminis.quic.packet.InitialPacket;

import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * This class is a test replacement for ServerConnectionThread; it has the same behaviour as ServerConnectionThread,
 * but does not execute on a separate thread (which makes testing difficult). Just like the ServerConnectionThread,
 * this class receives the first parse initial packet in its constructor and passes it to the ServerConnectionImpl.
 */
class ServerConnectionWrapper implements ServerConnectionProxy {
    private final ServerConnectionImpl connection;

    public ServerConnectionWrapper(ServerConnectionImpl connection, InitialPacket packet, Instant time, ByteBuffer data) {
        this.connection = connection;
        connection.parseAndProcessPackets(0, time, data, null, packet);
    }

    @Override
    public byte[] getOriginalDestinationConnectionId() {
        return connection.getOriginalDestinationConnectionId();
    }

    @Override
    public void parsePackets(int datagramNumber, Instant timeReceived, ByteBuffer data) {
        connection.parseAndProcessPackets(datagramNumber, timeReceived, data, null, null);
    }

    @Override
    public boolean isClosed() {
        return connection.isClosed();
    }

    @Override
    public void terminate() {
        connection.terminate();
    }
}
