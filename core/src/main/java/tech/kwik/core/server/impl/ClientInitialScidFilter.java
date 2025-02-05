/*
 * Copyright © 2025 Peter Doornbosch
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
package tech.kwik.core.server.impl;

import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.BaseDatagramFilter;
import tech.kwik.core.packet.DatagramFilter;
import tech.kwik.core.packet.InitialPacket;
import tech.kwik.core.packet.PacketMetaData;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Filter that ensure that the source connection id of an Initial packets matches the original source connection id.
 */
public class ClientInitialScidFilter extends BaseDatagramFilter {

    private final byte[] originalSourceConnectionId;

    public ClientInitialScidFilter(byte[] originalSourceConnectionId, Logger log, DatagramFilter next) {
        super(next, log);
        this.originalSourceConnectionId = originalSourceConnectionId;
    }

    @Override
    public void processDatagram(ByteBuffer data, PacketMetaData metaData) {
        data.mark();
        byte flags = data.get();
        int version = data.getInt();
        data.reset();

        if (InitialPacket.isInitial(flags, version)) {
            byte[] scid = extractSourceConnectionId(data);
            if (Arrays.equals(scid, originalSourceConnectionId)) {
                next(data, metaData);
            } else {
                discard(data, metaData,
                        String.format("Dropping packet with unmatched source connection id %s (expected %s).", scid, originalSourceConnectionId));
            }
        }
        else {
            next(data, metaData);
        }
    }

    byte[] extractSourceConnectionId(ByteBuffer data) {
        data.mark();
        int start = data.position();
        int dcidLength = data.get(start + 5) & 0xff;
        int scidLength = data.get(start + 5 + 1 + dcidLength) & 0xff;
        byte[] scid = new byte[scidLength];
        data.position(start + 5 + 1 + dcidLength + 1);
        data.get(scid);
        data.reset();
        return scid;
    }
}
