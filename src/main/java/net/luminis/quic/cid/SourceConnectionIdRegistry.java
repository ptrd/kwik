/*
 * Copyright © 2019 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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
package net.luminis.quic.cid;

import net.luminis.quic.log.Logger;
import net.luminis.tls.ByteUtils;

import java.util.Arrays;


public class SourceConnectionIdRegistry extends ConnectionIdRegistry {


    public SourceConnectionIdRegistry(Logger logger) {
        super(logger);
    }

    public ConnectionIdInfo generateNew() {
        int sequenceNr = connectionIds.keySet().stream().max(Integer::compareTo).get() + 1;
        ConnectionIdInfo newCid = new ConnectionIdInfo(sequenceNr, generateConnectionId(), ConnectionIdStatus.NEW);
        connectionIds.put(sequenceNr, newCid);
        return newCid;
    }

    public void registerUsedConnectionId(byte[] connectionId) {
        if (! Arrays.equals(currentConnectionId, connectionId)) {
            // Register previous connection id as used
            connectionIds.values().stream()
                    .filter(cid -> Arrays.equals(cid.getConnectionId(), currentConnectionId))
                    .forEach(cid -> cid.setStatus(ConnectionIdStatus.USED));
            currentConnectionId = connectionId;
            // Register current connection id as current
            connectionIds.values().stream()
                    .filter(cid -> Arrays.equals(cid.getConnectionId(), currentConnectionId))
                    .forEach(cid -> cid.setStatus(ConnectionIdStatus.IN_USE));
            log.info("Peer has switched to connection id " + ByteUtils.bytesToHex(currentConnectionId));
        }
    }


}


