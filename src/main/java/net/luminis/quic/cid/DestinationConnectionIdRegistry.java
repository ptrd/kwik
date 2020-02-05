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

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;


public class DestinationConnectionIdRegistry extends ConnectionIdRegistry {

    private final byte[] originalConnectionId;

    public DestinationConnectionIdRegistry(Logger log) {
        super(log);
        originalConnectionId = currentConnectionId;
    }

    public DestinationConnectionIdRegistry(byte[] initialConnectionId, Logger log) {
        super(log);
        originalConnectionId = initialConnectionId;
        currentConnectionId = initialConnectionId;
        connectionIds.put(0, new ConnectionIdInfo(0, initialConnectionId, ConnectionIdStatus.IN_USE));
    }

    public void replaceInitialConnectionId(byte[] connectionId) {
        connectionIds.put(0, new ConnectionIdInfo(0, connectionId, ConnectionIdStatus.IN_USE));
        currentConnectionId = connectionId;
    }

    public void registerNewConnectionId(int sequenceNr, byte[] connectionId) {
        connectionIds.put(sequenceNr, new ConnectionIdInfo(sequenceNr, connectionId, ConnectionIdStatus.NEW));
    }

    public byte[] useNext() {
        int currentIndex = currentIndex();
        if (connectionIds.containsKey(currentIndex + 1)) {
            currentConnectionId = connectionIds.get(currentIndex + 1).getConnectionId();
            connectionIds.get(currentIndex).setStatus(ConnectionIdStatus.USED);
            connectionIds.get(currentIndex+1).setStatus(ConnectionIdStatus.IN_USE);
            return currentConnectionId;
        }
        else {
            return null;
        }
    }

    public byte[] getOriginalConnectionId() {
        return originalConnectionId;
    }

    public List<Integer> retireAllBefore(int retirePriorTo) {
        int currentIndex = currentIndex();

        List<Integer> toRetire = connectionIds.entrySet().stream()
                .filter(entry -> entry.getKey() < retirePriorTo)
                .filter(entry -> !entry.getValue().getConnectionIdStatus().equals(ConnectionIdStatus.RETIRED))
                .map(entry -> entry.getKey())
                .collect(Collectors.toList());

        toRetire.forEach(seqNr -> retireConnectionId(seqNr));

        if (connectionIds.get(currentIndex).getConnectionIdStatus().equals(ConnectionIdStatus.RETIRED)) {
            // Find one that is not retired
            ConnectionIdInfo nextCid = connectionIds.values().stream()
                    .filter(cid -> !cid.getConnectionIdStatus().equals(ConnectionIdStatus.RETIRED))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Can't find connection id that is not retired"));
            nextCid.setStatus(ConnectionIdStatus.IN_USE);
            currentConnectionId = nextCid.getConnectionId();
        }

        return toRetire;
    }
}

