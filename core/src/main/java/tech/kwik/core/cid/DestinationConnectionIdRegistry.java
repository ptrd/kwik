/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Registry of the peer's connection IDs, which are used by this endpoint as destination connection IDs.
 * The peer issues these connection IDs and determines when they should be retired (but the actual retirement is done
 * by this endpoint).
 * It is up to this endpoint to determine which connection ID to use for a specific client address. It may use any
 * active connection ID at any time.
 * <p>
 * Implementation notes:
 * <ul>this class will use (consume) connection IDs in order of their sequence number (which is not a requirement of the
 * QUIC protocol, but is a logical choice given the fact that the peer can only ask to retire connection ID whose
 * sequence number is smaller than a given number);</ul>
 * <ul>when a new connection ID is being used for a given client address, the previous connection ID is never used again
 * (as no history is kept of which connection ID's have been used for which client address).</ul>
 */
public class DestinationConnectionIdRegistry extends ConnectionIdRegistry {

    private volatile int currentCidIndex;      // the highest index (sequence number) of connection IDs in use
    private volatile int notRetiredThreshold;  // all sequence numbers _below_ are retired
    private final Map<InetSocketAddress, ConnectionIdInfo> cidByClientAddress = new ConcurrentHashMap<>();


    public DestinationConnectionIdRegistry(byte[] initialConnectionId, Logger log) {
        super(log);
        connectionIds.put(0, new ConnectionIdInfo(0, initialConnectionId, ConnectionIdStatus.IN_USE));
    }

    /**
     * Replaces the initial connection ID. This is only used by clients, as they generate a random connection ID for
     * the first initial packet, that upon receipt of a server packet is immediately replaced by the connection ID of
     * the server.
     * @param connectionId
     */
    public void replaceInitialConnectionId(byte[] connectionId) {
        assert currentCidIndex == 0;
        ConnectionIdInfo oldCid = connectionIds.get(0);
        ConnectionIdInfo newCid = new ConnectionIdInfo(0, connectionId, ConnectionIdStatus.IN_USE);
        connectionIds.put(0, newCid);
        cidByClientAddress.forEach((k, cid) -> {
            if (cid == oldCid) {
                cidByClientAddress.put(k, newCid);
            }
        });
    }

    /**
     * Registers a new connection ID (together with it's stateless reset token).
     * @param sequenceNr
     * @param connectionId
     * @param statelessResetToken
     * @return  whether the connection id could be added as new; when its sequence number implies that it is retired
     *          already (which can happen when packets are delivered out of order), false is returned.
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
            return connectionIds.get(currentCidIndex).getConnectionId();
        }
        else {
            return null;
        }
    }

    /**
     * Retires all connection ID's with a sequence number smaller than the given index.
     * @param retirePriorTo
     * @return
     */
    public List<Integer> retireAllBefore(int retirePriorTo) {
        notRetiredThreshold = retirePriorTo;

        List<Integer> toRetire = connectionIds.entrySet().stream()
                .filter(entry -> entry.getKey() < retirePriorTo)
                .filter(entry -> !entry.getValue().getConnectionIdStatus().equals(ConnectionIdStatus.RETIRED))
                .map(entry -> entry.getKey())
                .collect(Collectors.toList());

        toRetire.forEach(seqNr -> markAsRetired(seqNr));

        cidByClientAddress.forEach((seqNr,cid) -> {
            if (cid.getConnectionIdStatus() == ConnectionIdStatus.RETIRED) {
                cidByClientAddress.remove(seqNr);
        }
        });

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
        ConnectionIdInfo oldCid = connectionIds.get(0);
        ConnectionIdInfo newCid = oldCid.addStatelessResetToken(statelessResetToken);
        connectionIds.put(0, newCid);
        cidByClientAddress.forEach((k, cid) -> {
            if (cid == oldCid) {
                cidByClientAddress.put(k, newCid);
            }
        });
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
                .anyMatch(cid -> MessageDigest.isEqual(cid.getStatelessResetToken(), tokenCandidate));
    }

    /**
     * Returns a connection ID that can be used for the given client address. The method does not have to always
     * return the same connection ID for the same client address, but it will always return a connection ID that is not
     * retired and it will never return a connection ID that has been used for a different client address.
     * @param clientAddress
     * @return
     * @throw IllegalStateException when connection ID's are exhausted
     */
    public byte[] getCurrent(InetSocketAddress clientAddress) {
        ConnectionIdInfo cidInfo = cidByClientAddress.computeIfAbsent(clientAddress, (address) -> {
            ConnectionIdInfo newCid = getFirstUnused();
            newCid.setStatus(ConnectionIdStatus.IN_USE);
            return newCid;
        });
        return cidInfo.getConnectionId();
    }

    private ConnectionIdInfo getFirstUnused() {
        Optional<ConnectionIdInfo> firstUnused = connectionIds.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .filter(e -> e.getValue().getConnectionIdStatus() == ConnectionIdStatus.NEW)
                .findFirst()
                .map(e -> e.getValue());

        return firstUnused.orElseThrow(() -> {
            // This should have been prevented by application logic:
            // - requested retirement is always combined with a new connection ID
            // - an endpoint should not trigger retirement itself when no new connection ID's are available
            // - path migration should be prevented when no new connectionID's are available
            log.error("Cannot get connection ID because new connections ID's are exhausted");
            return new IllegalStateException("new connection ID's are exhausted");
        });
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

