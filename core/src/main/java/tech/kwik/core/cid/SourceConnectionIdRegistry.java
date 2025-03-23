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
import tech.kwik.core.util.Bytes;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Registry of this endpoint's connection IDs. The peer uses these connection IDs as destination connection IDs.
 * This endpoint issues these connection IDs (initially, by set the source connection ID in the long header packets and
 * after the handshake by sending NewConnectionId frames), but the peer determines which connection ID to use: it can
 * use any active (not retired) connection ID at any time. Hence, there is no notion of a "current" connection ID.
 * Only during the handshake, the connection ID is fixed (except for a server using preferred address).
 *
 * https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1
 * "Each connection possesses a set of connection identifiers, or connection IDs, each of which can identify the
 *  connection. Connection IDs are independently selected by endpoints; each endpoint selects the connection IDs that
 *  its peer uses."
 *  https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1
 *  "The initial connection ID issued by an endpoint is sent in the Source Connection ID field of the long packet
 *   header (Section 17.2) during the handshake. The sequence number of the initial connection ID is 0. If the
 *   preferred_address transport parameter is sent, the sequence number of the supplied connection ID is 1."
 *  "Connection IDs that are issued and not retired are considered active; any active connection ID is valid for use
 *   with the current connection at any time, in any packet type. "
 */
public class SourceConnectionIdRegistry extends ConnectionIdRegistry {

    public static final int DEFAULT_CID_LENGTH = 8;

    protected final int connectionIdLength;
    protected final SecureRandom randomGenerator;
    protected volatile byte[] currentConnectionId;

    public SourceConnectionIdRegistry(Integer cidLength, Logger logger) {
        super(logger);
        connectionIdLength = cidLength != null? cidLength: DEFAULT_CID_LENGTH;
        randomGenerator = new SecureRandom();

        currentConnectionId = generateConnectionId();
        connectionIds.put(0, new ConnectionIdInfo(0, currentConnectionId, ConnectionIdStatus.IN_USE));
    }

    private byte[] generateConnectionId() {
        byte[] connectionId = new byte[connectionIdLength];
        randomGenerator.nextBytes(connectionId);
        return connectionId;
    }

    public ConnectionIdInfo generateNew() {
        int sequenceNr = connectionIds.keySet().stream().max(Integer::compareTo).get() + 1;
        ConnectionIdInfo newCid = new ConnectionIdInfo(sequenceNr, generateConnectionId(), ConnectionIdStatus.NEW);
        connectionIds.put(sequenceNr, newCid);
        return newCid;
    }

    /**
     * Registers a connection id for being used.
     * @param connectionId
     * @return true is the connection id is new (newly used), false otherwise.
     */
    public boolean registerUsedConnectionId(byte[] connectionId) {
        if (! Arrays.equals(currentConnectionId, connectionId)) {
            // Register previous connection id as used
            connectionIds.values().stream()
                    .filter(cid -> Arrays.equals(cid.getConnectionId(), currentConnectionId))
                    .forEach(cid -> cid.setStatus(ConnectionIdStatus.USED));
            currentConnectionId = connectionId;
            // Check if new connection id is newly used
            boolean wasNew = connectionIds.values().stream()
                    .filter(cid -> Arrays.equals(cid.getConnectionId(), currentConnectionId))
                    .anyMatch(cid -> cid.getConnectionIdStatus().equals(ConnectionIdStatus.NEW));
            // Register current connection id as current
            connectionIds.values().stream()
                    .filter(cid -> Arrays.equals(cid.getConnectionId(), currentConnectionId))
                    .forEach(cid -> cid.setStatus(ConnectionIdStatus.IN_USE));
            log.info("Peer has switched to connection id " + Bytes.bytesToHex(currentConnectionId));
            return wasNew;
        }
        else {
            return false;
        }
    }

    public int getMaxSequenceNr() {
        return connectionIds.keySet().stream().max(Integer::compareTo).get();
    }

    public byte[] get(int sequenceNr) {
        return connectionIds.get(sequenceNr).getConnectionId();
    }

    /**
     * Get an active connection ID. There can be multiple active connection IDs, this method returns an arbitrary one.
     * @return  an active connection ID or null if non is active (which should never happen).
     */
    public byte[] getActive() {
        return connectionIds.entrySet().stream()
                .filter(e -> e.getValue().getConnectionIdStatus().active())
                .map(e -> e.getValue().getConnectionId())
                .findFirst().orElse(null);
    }


    /**
     * Returns the initial source connection ID, which is the first connection ID issued by this endpoint.
     * This method should only be used during the handshake (as connection ID's may change after the handshake).
     * @return
     */
    public byte[] getInitialConnectionId() {
        return connectionIds.get(0).getConnectionId();
    }

    public int getConnectionIdlength() {
        return connectionIdLength;
    }
}


