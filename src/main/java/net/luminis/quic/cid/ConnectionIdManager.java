/*
 * Copyright © 2022 Peter Doornbosch
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
package net.luminis.quic.cid;

import net.luminis.quic.Version;
import net.luminis.quic.frame.NewConnectionIdFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.RetireConnectionIdFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.send.Sender;
import net.luminis.quic.server.ServerConnectionRegistry;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.BiConsumer;

import static net.luminis.quic.EncryptionLevel.App;
import static net.luminis.quic.QuicConstants.TransportErrorCode.*;

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
    private int maxPeerCids = 2;
    private Version quicVersion = Version.QUIC_version_1;


    /**
     * Creates a connection ID manager for server role.
     * @param initialClientCid  the initial connection ID of the client
     * @param connectionIdLength  the length of the connection ID's generated for this endpoint (server)
     * @param connectionRegistry  the connection registry for associating new connection IDs with the connection
     * @param sender  the sender to send messages to the peer
     * @param closeConnectionCallback  callback for closing the connection with a transport error code
     * @param log  logger
     */
    public ConnectionIdManager(byte[] initialClientCid, int connectionIdLength, ServerConnectionRegistry connectionRegistry, Sender sender,
                               BiConsumer<Integer, String> closeConnectionCallback, Logger log) {
        this.connectionIdLength = connectionIdLength;
        this.connectionRegistry = connectionRegistry;
        this.sender = sender;
        this.closeConnectionCallback = closeConnectionCallback;
        cidRegistry = new SourceConnectionIdRegistry(connectionIdLength, log);
        initialConnectionId = cidRegistry.currentConnectionId;

        if (initialClientCid != null && initialClientCid.length != 0) {
            peerCidRegistry = new DestinationConnectionIdRegistry(initialClientCid, log);
        }
        else {
            // If peer (client) uses zero-length connection ID, it cannot change, so a registry is not needed.
            peerCidRegistry = null;
        }
    }

    public void handshakeFinished() {
        for (int i = 1; i < maxPeerCids ; i++) {
            sendNewCid();
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
            peerCidRegistry.registerNewConnectionId(frame.getSequenceNr(), frame.getConnectionId(), frame.getStatelessResetToken());
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
        // active connection IDs exceeds the value advertised in its active_connection_id_limit transport parameter, an
        // endpoint MUST close the connection with an error of type CONNECTION_ID_LIMIT_ERROR."
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
            sendNewCid();
        }
    }

    public void setPeerCidLimit(int peerCidLimit) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids
        // "An endpoint MUST NOT provide more connection IDs than the peer's limit."
        maxPeerCids = Integer.min(peerCidLimit, MAX_CIDS_PER_CONNECTION);
    }

    private void sendNewCid() {
        ConnectionIdInfo cidInfo = cidRegistry.generateNew();
        connectionRegistry.registerAdditionalConnectionId(cidRegistry.getActive(), cidInfo.getConnectionId());
        sender.send(new NewConnectionIdFrame(quicVersion, cidInfo.getSequenceNumber(), 0, cidInfo.getConnectionId()),
                App, this::retransmitFrame);
    }

    private void retransmitFrame(QuicFrame frame) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-retransmission-of-informati
        // "New connection IDs are sent in NEW_CONNECTION_ID frames and retransmitted if the packet containing them is
        //  lost. Retransmissions of this frame carry the same sequence number value."
        sender.send(frame, App, this::retransmitFrame);
    }

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

    public byte[] getDestinationConnectionId() {
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
}
