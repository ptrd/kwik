/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.cid;

import tech.kwik.core.log.Logger;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;


public abstract class ConnectionIdRegistry {

    /** Maps sequence number to connection ID (info) */
    protected final Map<Integer, ConnectionIdInfo> connectionIds = new ConcurrentHashMap<>();
    protected final Logger log;

    public ConnectionIdRegistry(Logger log) {
        this.log = log;
    }

    public byte[] retireConnectionId(int sequenceNr) {
        if (connectionIds.containsKey(sequenceNr)) {
            ConnectionIdInfo cidInfo = connectionIds.get(sequenceNr);
            if (cidInfo.getConnectionIdStatus().active()) {
                cidInfo.setStatus(ConnectionIdStatus.RETIRED);
                return cidInfo.getConnectionId();
            }
            else {
                return null;
            }
        }
        else {
            return null;
        }
    }

    public Map<Integer, ConnectionIdInfo> getAll() {
        return connectionIds;
    }

    public List<byte[]> getActiveConnectionIds() {
        return connectionIds.values().stream()
                .filter(cid -> cid.getConnectionIdStatus().active())
                .map(info -> info.getConnectionId())
                .collect(Collectors.toList());
    }
}
