/*
 * Copyright © 2022, 2023, 2024, 2025 Peter Doornbosch
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

import tech.kwik.core.frame.NewConnectionIdFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.frame.RetireConnectionIdFrame;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.send.Sender;
import tech.kwik.core.server.ServerConnectionRegistry;
import tech.kwik.core.server.impl.ServerConnectionProxy;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.stream.Stream;

import static tech.kwik.core.QuicConstants.TransportErrorCode.CONNECTION_ID_LIMIT_ERROR;
import static tech.kwik.core.QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR;
import static tech.kwik.core.QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION;
import static tech.kwik.core.common.EncryptionLevel.App;

/**
 * Manages the collections of connection ID's for the connection, both for this (side of the) connection and the peer's.
 */
public class ConnectionIdManager {

    public static final int MAX_CIDS_PER_CONNECTION = 6;

    private final int connectionIdLength;
    private final ServerConnectionRegistry connectionRegistry;
    private final Sender sender;
    private final BiConsumer<Integer, String> closeConnectionCallback;
    private final SourceConnectionIdRegistry cidRegistry;
    private final DestinationConnectionIdRegistry peerCidRegistry;
    private final byte[] initialConnectionId;
    private final byte[] initialPeerConnectionId;
    private final byte[] originalDestinationConnectionId;
    /** The maximum numbers of connection IDs this endpoint can use; determined by the TP supplied by the peer */
    private volatile int maxCids = 2;
    /** The maximum number of peer connection IDs this endpoint is willing to maintain; advertised in TP sent by this endpoint */
    private volatile int maxPeerCids;
    private volatile byte[] retrySourceCid;
    private final Version quicVersion = Version.QUIC_version_1;


    /**
     * Creates a connection ID manager for server role.
     * @param initialClientCid  the initial connection ID of the client
     * @param originalDestinationConnectionId
     * @param connectionIdLength  the length of the connection IDs generated for this endpoint (server)
     * @param maxPeerCids  the maximum number of peer connection IDs this endpoint is willing to store
     * @param connectionRegistry  the connection registry for associating new connection IDs with the connection
     * @param sender  the sender to send messages to the peer
     * @param closeConnectionCallback  callback for closing the connection with a transport error code
     * @param log  logger
     */
    public ConnectionIdManager(byte[] initialClientCid, byte[] originalDestinationConnectionId, int connectionIdLength,
                               int maxPeerCids, ServerConnectionRegistry connectionRegistry, Sender sender,
                               BiConsumer<Integer, String> closeConnectionCallback, Logger log) {
        this.originalDestinationConnectionId = originalDestinationConnectionId;
        this.connectionIdLength = connectionIdLength;
        this.maxPeerCids = maxPeerCids;
        this.connectionRegistry = connectionRegistry;
        this.sender = sender;
        this.closeConnectionCallback = closeConnectionCallback;
        cidRegistry = new SourceConnectionIdRegistry(connectionIdLength, log);
        initialConnectionId = cidRegistry.currentConnectionId;

        if (initialClientCid != null && initialClientCid.length != 0) {
            peerCidRegistry = new DestinationConnectionIdRegistry(initialClientCid, log);
            initialPeerConnectionId = initialClientCid;
        }
        else {
            // If peer (client) uses zero-length connection ID, it cannot change, so a registry is not needed.
            peerCidRegistry = null;
            initialPeerConnectionId = new byte[0];
        }
    }

    /**
     * Creates a connection ID manager for client role.
     * @param connectionIdLength  the length of the connection ID's generated for this endpoint (client)
     * @param maxPeerCids  the maximum number of peer connection IDs this endpoint is willing to store
     * @param sender  the sender to send messages to the peer
     * @param closeConnectionCallback  callback for closing the connection with a transport error code
     * @param log  logger
     */
    public ConnectionIdManager(Integer connectionIdLength, int maxPeerCids, Sender sender, BiConsumer<Integer, String> closeConnectionCallback, Logger log) {
        this.maxPeerCids = maxPeerCids;
        this.sender = sender;
        cidRegistry = new SourceConnectionIdRegistry(connectionIdLength, log);
        this.connectionIdLength = cidRegistry.getConnectionIdlength();
        initialConnectionId = cidRegistry.getCurrent();
        this.closeConnectionCallback = closeConnectionCallback;

        // https://www.rfc-editor.org/rfc/rfc9000.html#name-negotiating-connection-ids
        // "When an Initial packet is sent by a client (...), the client populates the Destination Connection ID field
        //  with an unpredictable value. This Destination Connection ID MUST be at least 8 bytes in length."
        originalDestinationConnectionId = new byte[8];
        new SecureRandom().nextBytes(originalDestinationConnectionId);

        peerCidRegistry = new DestinationConnectionIdRegistry(originalDestinationConnectionId, log);
        initialPeerConnectionId = originalDestinationConnectionId;

        connectionRegistry = new ServerConnectionRegistry() {   // TODO
            @Override
            public void registerConnection(ServerConnectionProxy connection, byte[] connectionId) {}

            @Override
            public void deregisterConnection(ServerConnectionProxy connection, byte[] connectionId) {}

            @Override
            public void registerAdditionalConnectionId(byte[] currentConnectionId, byte[] newConnectionId) {}

            @Override
            public void deregisterConnectionId(byte[] connectionId) {}

            @Override
            public Stream<ServerConnectionProxy> getAllConnections() {
                return Stream.empty();
            }
        };
    }

    public void handshakeFinished() {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids
        // "An endpoint SHOULD ensure that its peer has a sufficient number of available and unused connection IDs."
        // "The initial connection ID issued by an endpoint is sent in the Source Connection ID field of the long
        //  packet header (Section 17.2) during the handshake."
        for (int i = 1; i < maxCids; i++) {
            sendNewCid(0);
        }
    }

    public void process(NewConnectionIdFrame frame) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-new_connection_id-frames
        // "An endpoint that is sending packets with a zero-length Destination Connection ID MUST treat receipt of a
        //  NEW_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION."
        if (peerCidRegistry == null) {
            closeConnectionCallback.accept((int) PROTOCOL_VIOLATION.value, "new connection id frame not allowed when using zero-length connection ID");
            return;
        }

        // https://www.rfc-editor.org/rfc/rfc9000.html#name-new_connection_id-frames
        // "Receiving a value in the Retire Prior To field that is greater than that in the Sequence Number field MUST
        //  be treated as a connection error of type FRAME_ENCODING_ERROR."
        if (frame.getRetirePriorTo() > frame.getSequenceNr()) {
            closeConnectionCallback.accept((int) FRAME_ENCODING_ERROR.value, "exceeding active connection id limit");
            return;
        }
        if (!peerCidRegistry.connectionIds.containsKey(frame.getSequenceNr())) {
            boolean added = peerCidRegistry.registerNewConnectionId(frame.getSequenceNr(), frame.getConnectionId(), frame.getStatelessResetToken());
            if (! added) {
                // https://www.rfc-editor.org/rfc/rfc9000.html#name-new_connection_id-frames
                // "An endpoint that receives a NEW_CONNECTION_ID frame with a sequence number smaller than the Retire Prior To
                //  field of a previously received NEW_CONNECTION_ID frame MUST send a corresponding RETIRE_CONNECTION_ID
                //  frame that retires the newly received connection ID, "
                sendRetireCid(frame.getSequenceNr());
            }
        }
        else if (! Arrays.equals(peerCidRegistry.connectionIds.get(frame.getSequenceNr()).getConnectionId(), frame.getConnectionId())) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-new_connection_id-frames
            // "... or if a sequence number is used for different connection IDs, the endpoint MAY treat that receipt as a
            //  connection error of type PROTOCOL_VIOLATION."
            closeConnectionCallback.accept((int) PROTOCOL_VIOLATION.value, "different cids or same sequence number");
            return;
        }
        if (frame.getRetirePriorTo() > 0) {
            List<Integer> retired = peerCidRegistry.retireAllBefore(frame.getRetirePriorTo());
            retired.forEach(seqNr -> sendRetireCid(seqNr));
        }
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids
        // "After processing a NEW_CONNECTION_ID frame and adding and retiring active connection IDs, if the number of
        //  active connection IDs exceeds the value advertised in its active_connection_id_limit transport parameter, an
        //  endpoint MUST close the connection with an error of type CONNECTION_ID_LIMIT_ERROR."
        if (peerCidRegistry.getActiveConnectionIds().size() > maxPeerCids) {
            closeConnectionCallback.accept((int) CONNECTION_ID_LIMIT_ERROR.value, "exceeding active connection id limit");
            return;
        }
    }

    public void process(RetireConnectionIdFrame frame, byte[] destinationConnectionId) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-retire_connection_id-frames
        // "Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number greater than any previously sent to the
        //  peer MUST be treated as a connection error of type PROTOCOL_VIOLATION."
        if (frame.getSequenceNr() > cidRegistry.getMaxSequenceNr()) {
            closeConnectionCallback.accept((int) PROTOCOL_VIOLATION.value, "invalid connection ID sequence number");
            return;
        }
        int sequenceNr = frame.getSequenceNr();
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-retire_connection_id-frames
        // "The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer to the
        //  Destination Connection ID field of the packet in which the frame is contained. The peer MAY treat this as
        //  a connection error of type PROTOCOL_VIOLATION."
        if (Arrays.equals(cidRegistry.get(sequenceNr), destinationConnectionId)) {
            closeConnectionCallback.accept((int) PROTOCOL_VIOLATION.value, "cannot retire current connection ID");
            return;
        }

        byte[] retiredCid = cidRegistry.retireConnectionId(sequenceNr);
        // If not retired already
        if (retiredCid != null) {
            connectionRegistry.deregisterConnectionId(retiredCid);
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids
            // "An endpoint SHOULD supply a new connection ID when the peer retires a connection ID."
            if (cidRegistry.getActiveConnectionIds().size() < maxCids) {
                sendNewCid(0);
            }
        }
    }

    /**
     * Sets the maximum number of peer connection IDs this endpoint is willing to store. This should be the same number
     * as this endpoint sends in the TP active_connection_id_limit.
     * @param maxPeerCids  the maximum number of peer connection IDs this endpoint is willing to store
     */
    public void setMaxPeerConnectionIds(int maxPeerCids) {
        this.maxPeerCids = maxPeerCids;
    }

    /**
     * Register the active connection ID limit of the peer (as received by this endpoint as TP active_connection_id_limit)
     * and determine the maximum number of peer connection ID's this endpoint is willing to maintain.
     * "This is an integer value specifying the maximum number of connection IDs from the peer that an endpoint is
     *  willing to store.", so it puts an upper bound to the number of connection IDs this endpoint can generate.
     * @param peerCidLimit
     */
    public void registerPeerCidLimit(int peerCidLimit) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids
        // "An endpoint MUST NOT provide more connection IDs than the peer's limit."
        // This implementation also sets a limit on the number of connection IDs it is willing to maintain, so
        maxCids = Integer.min(peerCidLimit, MAX_CIDS_PER_CONNECTION);
    }

    /**
     * Generate, register and send a new connection ID (that identifies this endpoint).
     * @param retirePriorTo
     * @return
     */
    private ConnectionIdInfo sendNewCid(int retirePriorTo) {
        ConnectionIdInfo cidInfo = cidRegistry.generateNew();
        connectionRegistry.registerAdditionalConnectionId(cidRegistry.getActive(), cidInfo.getConnectionId());
        sender.send(new NewConnectionIdFrame(quicVersion, cidInfo.getSequenceNumber(), retirePriorTo, cidInfo.getConnectionId()),
                App, this::retransmitFrame);
        return cidInfo;
    }

    private void retransmitFrame(QuicFrame frame) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-retransmission-of-informati
        // "New connection IDs are sent in NEW_CONNECTION_ID frames and retransmitted if the packet containing them is
        //  lost. Retransmissions of this frame carry the same sequence number value."
        sender.send(frame, App, this::retransmitFrame);
    }

    /**
     * Send a retire connection ID frame, that informs the peer the given connection ID will not be used by this
     * endpoint anymore for addressing the peer.
     * @param seqNr
     */
    private void sendRetireCid(Integer seqNr) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-retransmission-of-informati
        // "Likewise, retired connection IDs are sent in RETIRE_CONNECTION_ID frames and retransmitted if the packet
        //  containing them is lost."
        sender.send(new RetireConnectionIdFrame(quicVersion, seqNr), App, this::retransmitFrame);
    }

    /**
     * Returns all active connection IDs.
     * https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids:
     * "Connection IDs that are issued and not retired are considered active; any active connection ID is valid for use
     *  with the current connection at any time, in any packet type. "
     * @return  all active connection IDs
     */
    public List<byte[]> getActiveConnectionIds() {
        return cidRegistry.getActiveConnectionIds();
    }

    public List<byte[]> getActivePeerConnectionIds() {
        if (peerCidRegistry != null) {
            return peerCidRegistry.getActiveConnectionIds();
        }
        else {
            return List.of(new byte[0]);
        }
    }

    /**
     * Returns the (peer's) connection ID that is currently used by this endpoint to address the peer.
     * @return
     */
    public byte[] getCurrentPeerConnectionId() {
        if (peerCidRegistry != null) {
            return peerCidRegistry.getCurrent();
        }
        else {
            return new byte[0];
        }
    }

    /**
     * Retrieves the initial connection used by this endpoint. This is the value that the endpoint included in the
     * Source Connection ID field of the first Initial packet it sends/send for the connection.
     * @return the initial connection id
     */
    public byte[] getInitialConnectionId() {
        return initialConnectionId;
    }

    /**
     * Returns the original destination connection ID, i.e. the connection ID the client used as destination in its
     * very first initial packet.
     * @return
     */
    public byte[] getOriginalDestinationConnectionId() {
        return originalDestinationConnectionId;
    }

    /**
     * Validates the given connection ID equals the initial peer connection ID.
     * @param connectionId
     * @return  true if given connection ID equals the initial peer connection ID, false otherwise.
     */
    public boolean validateInitialPeerConnectionId(byte[] connectionId) {
        return Arrays.equals(connectionId, initialPeerConnectionId);
    }

    /**
     * Registers that the given connection is used by the peer (as destination connection ID) to send messages to this
     * endpoint.
     * @param  connectionId  the connection ID used
     */
    public void registerConnectionIdInUse(byte[] connectionId) {
        if (cidRegistry.registerUsedConnectionId(connectionId)) {
            // New connection id, not used before.
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids
            // "If an endpoint provided fewer connection IDs than the peer's active_connection_id_limit, it MAY supply
            //  a new connection ID when it receives a packet with a previously unused connection ID."
            if (cidRegistry.getActiveConnectionIds().size() < maxCids) {
                sendNewCid(0);
            }
        }
    }

    /**
     * Generates a new connection ID for this endpoint and sends it to the peer.
     * @return
     * @param retirePriorTo
     */
    public ConnectionIdInfo sendNewConnectionId(int retirePriorTo) {
        return sendNewCid(retirePriorTo);
    }

    /**
     * Registers the source connection ID used in the (received) retry packet.
     * @param connectionId  the connection ID used in the (received) retry packet.
     */
    public void registerRetrySourceConnectionId(byte[] connectionId) {
        retrySourceCid = connectionId;
    }

    /**
     * Validates the  source connection ID used in the (received) retry packet.
     * @param connectionId  the connection ID used in the (received) retry packet.
     * @return  true if the given connection ID matches the retry source connection id registered earlier.
     */
    public boolean validateRetrySourceConnectionId(byte[] connectionId) {
        return Arrays.equals(retrySourceCid, connectionId);
    }

    /**
     * Registers the initial connection ID issued by the peer (server). Used in client role only.
     * @param connectionId
     */
    public void registerInitialPeerCid(byte[] connectionId) {
        peerCidRegistry.replaceInitialConnectionId(connectionId);
    }

    /**
     * Registers the stateless reset token for the initial connection ID. Used in client role only.
     * @param statelessResetToken
     */
    public void setInitialStatelessResetToken(byte[] statelessResetToken) {
        peerCidRegistry.setInitialStatelessResetToken(statelessResetToken);
    }

    /**
     * Determines whether the given token is a stateless reset token
     * @param data
     * @return
     */
    public boolean isStatelessResetToken(byte[] data) {
        return peerCidRegistry.isStatelessResetToken(data);
    }

    /**
     * Returns the length of the connection ID (or connection ID's) of this endpont.
     * @return
     */
    public int getConnectionIdLength() {
        return connectionIdLength;
    }

    /**
     * Returns all existing connection ID's for this endpoint, irrespective of its status (active or retired).
     * @return
     */
    public Map<Integer, ConnectionIdInfo> getAllConnectionIds() {
        return cidRegistry.getAll();
    }

    /**
     * Returns all known connection ID's for the peer, irrespective of its status (active or retired).
     * @return
     */
    public Map<Integer, ConnectionIdInfo> getAllPeerConnectionIds() {
        return peerCidRegistry.getAll();
    }

    /**
     * Switches the connection ID currently used by this endpoint to address the peer, to the next available.
     * The connection ID that was previously used is not being retired by this method.
     * @return
     */
    public byte[] nextPeerId() {
        return peerCidRegistry.useNext();
    }

    /**
     * Retires the given connection ID.
     * @param sequenceNumber
     */
    public void retireConnectionId(Integer sequenceNumber) {
        peerCidRegistry.retireConnectionId(sequenceNumber);
        sender.send(new RetireConnectionIdFrame(quicVersion, sequenceNumber), App, lostFrame -> retireConnectionId(sequenceNumber));
    }

    /**
     * Returns the connection ID that this endpoint considers as "current".
     * Note that in QUIC, there is no such thing as a "current" connection ID, there are only active and retired
     * connection ID's. The peer can use any time any active connection ID.
     * @return
     */
    public byte[] getCurrentConnectionId() {
        return cidRegistry.getActive();
    }

    /**
     * Returns whether the given connection ID is currently active (as connection ID for this endpoint).
     * @param cid
     * @return
     */
    public boolean isActiveCid(byte[] cid) {
        return getActiveConnectionIds().stream().anyMatch(activeCid -> Arrays.equals(activeCid, cid));
    }
}
