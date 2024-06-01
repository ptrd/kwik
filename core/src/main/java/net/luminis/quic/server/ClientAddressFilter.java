/*
 * Copyright © 2023, 2024 Peter Doornbosch
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

import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.BaseDatagramFilter;
import net.luminis.quic.packet.DatagramFilter;
import net.luminis.quic.packet.PacketMetaData;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class ClientAddressFilter extends BaseDatagramFilter {

    private final InetSocketAddress clientAddress;

    public ClientAddressFilter(InetSocketAddress clientAddress, Logger log, DatagramFilter next) {
        super(next, log);
        this.clientAddress = clientAddress;
    }

    @Override
    public void processDatagram(ByteBuffer data, PacketMetaData metaData) {
        if (metaData.sourceAddress().equals(clientAddress)) {
            next(data, metaData);
        }
        else {
            discard(data, metaData,
                    String.format("Dropping packet with unmatched source address %s (expected %s).", metaData.sourceAddress(), clientAddress));
        }

    }
}
