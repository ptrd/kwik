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
package net.luminis.quic.server;

import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.LongHeaderPacket;
import net.luminis.tls.util.ByteUtils;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;


/**
 * A filtering server connection proxy that only allows initial packets to pass the filter.
 */
public class InitialPacketFilterProxy implements ServerConnectionProxy {

    private final ServerConnectionProxy connectionCandidate;
    private final Version version;
    private final Logger log;

    public InitialPacketFilterProxy(ServerConnectionProxy connectionCandidate, Version version, Logger log) {
        this.connectionCandidate = connectionCandidate;
        this.version = version;
        this.log = log;
    }

    @Override
    public byte[] getOriginalDestinationConnectionId() {
        return connectionCandidate.getOriginalDestinationConnectionId();
    }

    @Override
    public void parsePackets(int datagramNumber, Instant timeReceived, ByteBuffer data, InetSocketAddress sourceAddress) {
        data.mark();
        byte flags = data.get();
        data.reset();
        if (LongHeaderPacket.isLongHeaderPacket(flags, version) &&
                InitialPacket.isInitial((flags & 0x30) >> 4, version)) {
            connectionCandidate.parsePackets(datagramNumber, timeReceived, data, sourceAddress);
        }
        else {
            log.info(String.format("Dropping packet (%d bytes) sent to odcid %s.", data.remaining(), ByteUtils.bytesToHex(getOriginalDestinationConnectionId())));
        }
    }

    @Override
    public boolean isClosed() {
        return connectionCandidate.isClosed();
    }

    @Override
    public void terminate() {
        connectionCandidate.terminate();
    }
}
