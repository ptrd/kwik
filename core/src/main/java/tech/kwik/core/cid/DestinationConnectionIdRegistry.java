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

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Registry of the peer's connection IDs, which are used by this endpoint as destination connection IDs.
 * The peer issues these connection IDs and determines when they are retired.
 * It is up to this endpoint to determine which connection ID to use for a specific client address.
 */
public class DestinationConnectionIdRegistry extends ConnectionIdRegistry {

    private volatile int notRetiredThreshold;  // all sequence numbers below are retired
    private final Map<InetSocketAddress, ConnectionIdInfo> cidByClientAddress = new ConcurrentHashMap<>();


    public DestinationConnectionIdRegistry(byte[] initialConnectionId, Logger log) {
        super(log);
        currentConnectionId = initialConnectionId;
        connectionIds.put(0, new ConnectionIdInfo(0, initialConnectionId, ConnectionIdStatus.IN_USE));
    }

    public void replaceInitialConnectionId(byte[] connectionId) {
        InetSocketAddress currentAddress = getCurrentAddress();
        connectionIds.put(0, new ConnectionIdInfo(0, connectionId, ConnectionIdStatus.IN_USE));
        currentConnectionId = connectionId;
        cidByClientAddress.put(currentAddress, connectionIds.get(0));
    }

    /**
     * @param sequenceNr
     * @param connectionId
     * @param statelessResetToken
     * @return  whether the connection id could be added as new; when its sequence number implies that it as retired already, false is returned.
     */
    public boolean registerNewConnectionId(int sequenceNr, byte[] connectionId, byte[] statelessResetToken) {
        if (sequenceNr >= notRetiredThreshold) {
            connectionIds.put(sequenceNr, new ConnectionIdInfo(sequenceNr, connectionId, ConnectionIdStatus.NEW, statelessResetToken));
            return true;
        }
        else {
            connectionIds.put(sequenceNr, new ConnectionIdInfo(sequenceNr, connectionId, ConnectionIdStatus.RETIRED, statelessResetToken));
            return false;
        }
    }

    public byte[] useNext() {
        int currentIndex = currentIndex();
        if (connectionIds.containsKey(currentIndex + 1)) {
            InetSocketAddress currentAddress = getCurrentAddress();
            currentConnectionId = connectionIds.get(currentIndex + 1).getConnectionId();
            connectionIds.get(currentIndex).setStatus(ConnectionIdStatus.USED);
            connectionIds.get(currentIndex+1).setStatus(ConnectionIdStatus.IN_USE);
            cidByClientAddress.put(currentAddress, connectionIds.get(currentIndex+1));
            return currentConnectionId;
        }
        else {
            return null;
        }
    }

    private InetSocketAddress getCurrentAddress() {
        InetSocketAddress currentAddress = cidByClientAddress.entrySet().stream()
                .filter(entry -> Arrays.equals(entry.getValue().getConnectionId(), currentConnectionId))
                .map(entry -> entry.getKey())
                .findAny()
                .get();
        return currentAddress;
    }

    public List<Integer> retireAllBefore(int retirePriorTo) {
        notRetiredThreshold = retirePriorTo;
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

    public void setInitialStatelessResetToken(byte[] statelessResetToken) {
        connectionIds.put(0, connectionIds.get(0).addStatelessResetToken(statelessResetToken));
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9000.html#name-detecting-a-stateless-reset
     * "... but excludes stateless reset tokens associated with connection IDs that are either unused or retired."
     * @param tokenCandidate
     * @return
     */
    public boolean isStatelessResetToken(byte[] tokenCandidate) {
        return connectionIds.values().stream()
                .filter(cid -> cid.getConnectionIdStatus().notUnusedOrRetired())
                .anyMatch(cid -> Arrays.equals(cid.getStatelessResetToken(), tokenCandidate));
    }

    public byte[] getCurrent(InetSocketAddress clientAddress) {
        cidByClientAddress.computeIfAbsent(clientAddress, (address) -> {
            int currentIndex = currentIndex();
            if (connectionIds.containsKey(currentIndex + 1)) {
                connectionIds.get(currentIndex).setStatus(ConnectionIdStatus.USED);
                ConnectionIdInfo newCid = connectionIds.get(currentIndex + 1);
                newCid.setStatus(ConnectionIdStatus.IN_USE);
                return newCid;
            }
            else {
                // So no new (unused) connection ID. Re-use current, let caller decide whether this is appropriate for
                // the situation.
                return connectionIds.get(currentIndex);
            }
        });
        return cidByClientAddress.get(clientAddress).getConnectionId();
    }

    public void registerClientAddress(InetSocketAddress clientAddress) {
        assert(cidByClientAddress.isEmpty() || cidByClientAddress.get(clientAddress).equals(connectionIds.get(0)));
        cidByClientAddress.put(clientAddress, connectionIds.get(0));
    }

    /**
     * Returns the max connection ID length of currently active connection IDs.
     * @return
     */
    @Override
    public int getConnectionIdlength() {
        return connectionIds.values().stream()
                .filter(cid -> cid.getConnectionIdStatus().active())
                .mapToInt(cid -> cid.getConnectionId().length)
                .max()
                .getAsInt();
    }
}

