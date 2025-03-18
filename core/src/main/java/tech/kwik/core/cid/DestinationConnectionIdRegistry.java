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
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Registry of the peer's connection IDs, which are used by this endpoint as destination connection IDs.
 * The peer issues these connection IDs and determines when they are retired.
 * It is up to this endpoint to determine which connection ID to use for a specific client address.
 */
public class DestinationConnectionIdRegistry extends ConnectionIdRegistry {

    private volatile int currentCidIndex;
    private volatile int notRetiredThreshold;  // all sequence numbers below are retired
    private final Map<InetSocketAddress, ConnectionIdInfo> cidByClientAddress = new ConcurrentHashMap<>();


    public DestinationConnectionIdRegistry(byte[] initialConnectionId, Logger log) {
        super(log);
        currentCidIndex = 0;
        connectionIds.put(currentCidIndex, new ConnectionIdInfo(0, initialConnectionId, ConnectionIdStatus.IN_USE));
    }

    public void replaceInitialConnectionId(byte[] connectionId) {
        connectionIds.put(currentCidIndex, new ConnectionIdInfo(0, connectionId, ConnectionIdStatus.IN_USE));
        cidByClientAddress.clear();
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
        int previousCidIndex = currentCidIndex;
        Optional<Integer> nextCidIndex = findNextIndex();
        if (nextCidIndex.isPresent()) {
            currentCidIndex = nextCidIndex.get();
            connectionIds.get(previousCidIndex).setStatus(ConnectionIdStatus.USED);
            cidByClientAddress.clear();
            connectionIds.get(currentCidIndex).setStatus(ConnectionIdStatus.IN_USE);
            return connectionIds.get(currentCidIndex).getConnectionId();
        }
        else {
            return null;
        }
    }

    public List<Integer> retireAllBefore(int retirePriorTo) {
        notRetiredThreshold = retirePriorTo;

        List<Integer> toRetire = connectionIds.entrySet().stream()
                .filter(entry -> entry.getKey() < retirePriorTo)
                .filter(entry -> !entry.getValue().getConnectionIdStatus().equals(ConnectionIdStatus.RETIRED))
                .map(entry -> entry.getKey())
                .collect(Collectors.toList());

        toRetire.forEach(seqNr -> retireConnectionId(seqNr));

        if (connectionIds.get(currentCidIndex).getConnectionIdStatus().equals(ConnectionIdStatus.RETIRED)) {
            cidByClientAddress.clear();
            currentCidIndex = findNextIndex()
                    // will never here, as this is called from processing a NewConnectionID frame, which implies that a new connection ID is available
                    .orElseThrow(() -> new IllegalStateException("Can't find connection id that is not retired"));
            connectionIds.get(currentCidIndex).setStatus(ConnectionIdStatus.IN_USE);
        }

        return toRetire;
    }

    private Optional<Integer> findNextIndex() {
        return connectionIds.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .filter(e -> e.getKey() > currentCidIndex)
                .filter(e -> e.getValue().getConnectionIdStatus().notRetired())
                .map(e -> e.getKey())
                .findFirst();
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
            boolean currentIsInUse = cidByClientAddress.values().stream().anyMatch(cid -> cid.getSequenceNumber() == currentCidIndex);
            if (currentIsInUse) {
                findNextIndex().ifPresent(cid -> currentCidIndex = cid);
                // or else (no new (unused) connection ID):
                // Re-use current, let caller decide whether this is appropriate for the situation.
                connectionIds.get(currentCidIndex).setStatus(ConnectionIdStatus.IN_USE);
            }
            return connectionIds.get(currentCidIndex);
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
    public int getConnectionIdlength() {
        return connectionIds.values().stream()
                .filter(cid -> cid.getConnectionIdStatus().active())
                .mapToInt(cid -> cid.getConnectionId().length)
                .max()
                .getAsInt();
    }
}

