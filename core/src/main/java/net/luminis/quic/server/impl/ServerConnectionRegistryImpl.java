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
package net.luminis.quic.server.impl;

import net.luminis.quic.log.Logger;
import net.luminis.quic.server.ServerConnectionRegistry;
import net.luminis.quic.util.Bytes;

import java.net.InetSocketAddress;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class ServerConnectionRegistryImpl implements ServerConnectionRegistry {

    private final Logger log;
    private final Map<ConnectionSource, ServerConnectionProxy> currentConnections;

    ServerConnectionRegistryImpl(Logger log) {
        this.log = log;
        currentConnections = new ConcurrentHashMap<>();
    }

    @Override
    public void registerConnection(ServerConnectionProxy connection, byte[] connectionId) {
        currentConnections.put(new ConnectionSource(connectionId), connection);
    }

    @Override
    public void deregisterConnection(ServerConnectionProxy connection, byte[] connectionId) {
        currentConnections.remove(new ConnectionSource(connectionId));
    }

    @Override
    public void registerAdditionalConnectionId(byte[] currentConnectionId, byte[] newConnectionId) {
        ServerConnectionProxy connection = currentConnections.get(new ConnectionSource(currentConnectionId));
        if (connection != null) {
            currentConnections.put(new ConnectionSource(newConnectionId), connection);
        }
        else {
            log.error("Cannot add additional cid to non-existing connection " + Bytes.bytesToHex(currentConnectionId));
        }
    }

    @Override
    public void deregisterConnectionId(byte[] connectionId) {
        currentConnections.remove(new ConnectionSource(connectionId));
    }

    Optional<ServerConnectionProxy> isExistingConnection(InetSocketAddress clientAddress, byte[] dcid) {
        return Optional.ofNullable(currentConnections.get(new ConnectionSource(dcid)));
    }

    ServerConnectionProxy removeConnection(ServerConnectionImpl connection) {
        // Remove the entry this is registered with the original dcid
        ServerConnectionProxy removed = currentConnections.remove(new ConnectionSource(connection.getOriginalDestinationConnectionId()));

        // Remove all entries that are registered with the active cids
        List<ServerConnectionProxy> removedConnections = connection.getActiveConnectionIds().stream()
                .map(cid -> new ConnectionSource(cid))
                .map(cs -> currentConnections.remove(cs))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        // For the active connection IDs, all entries must have pointed to the same connection.
        if (removedConnections.stream().distinct().count() != 1) {
            log.error("Removed connections for set of active connection IDs are not all referring to the same connection.");
        }

        if (! connection.isClosed()) {
            log.error("Removed connection with dcid " + Bytes.bytesToHex(connection.getOriginalDestinationConnectionId()) + " that is not closed.");
        }

        // Preferably, return the object registered with one of the active cid's, otherwise the one registered with the original dcid.
        return removedConnections.stream().findAny().orElse(removed);
    }

    boolean isEmpty() {
        return currentConnections.isEmpty();
    }

    /**
     * Logs the entire connection table. For debugging purposed only.
     */
    void logConnectionTable() {
        log.info("Connection table: \n" +
                currentConnections.entrySet().stream()
                        .sorted(new Comparator<Map.Entry<ConnectionSource, ServerConnectionProxy>>() {
                            @Override
                            public int compare(Map.Entry<ConnectionSource, ServerConnectionProxy> o1, Map.Entry<ConnectionSource, ServerConnectionProxy> o2) {
                                return o1.getValue().toString().compareTo(o2.getValue().toString());
                            }
                        })
                        .map(e -> e.getKey() + "->" + e.getValue())
                        .collect(Collectors.joining("\n")));

    }
}
