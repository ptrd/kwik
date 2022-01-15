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
import net.luminis.quic.log.Logger;
import net.luminis.quic.send.Sender;
import net.luminis.quic.server.ServerConnectionRegistry;

import static net.luminis.quic.EncryptionLevel.App;

/**
 * Manages the collections of connection ID's for the connection, both for this (side of the) connection and the peer's.
 */
public class ConnectionIdManager {

    public static final int MAX_CIDS_PER_CONNECTION = 6;

    private final int connectionIdLength;
    private final ServerConnectionRegistry connectionRegistry;
    private final Sender sender;
    private final SourceConnectionIdRegistry cidRegistry;
    private int maxPeerCids;
    private Version quicVersion = Version.QUIC_version_1;


    public ConnectionIdManager(int connectionIdLength, ServerConnectionRegistry connectionRegistry, Sender sender, Logger log) {
        this.connectionIdLength = connectionIdLength;
        this.connectionRegistry = connectionRegistry;
        this.sender = sender;
        cidRegistry = new SourceConnectionIdRegistry(connectionIdLength, log);
    }

    public byte[] getCurrentConnectionId() {
        return cidRegistry.getCurrent();
    }

    public void handshakeFinished() {
        for (int i = 1; i < maxPeerCids ; i++) {
            ConnectionIdInfo cidInfo = cidRegistry.generateNew();
            connectionRegistry.registerAdditionalConnectionId(cidRegistry.getCurrent(), cidInfo.getConnectionId());
            sender.send(new NewConnectionIdFrame(quicVersion, cidInfo.getSequenceNumber(), 0, cidInfo.getConnectionId()),
                    App, this::retransmitFrame);
        }
    }

    private void retransmitFrame(QuicFrame frame) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-retransmission-of-informati
        // "New connection IDs are sent in NEW_CONNECTION_ID frames and retransmitted if the packet containing them is
        //  lost. Retransmissions of this frame carry the same sequence number value."
        sender.send(frame, App, this::retransmitFrame);
    }

    public void setPeerCidLimit(int peerCidLimit) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-issuing-connection-ids
        // "An endpoint MUST NOT provide more connection IDs than the peer's limit."
        maxPeerCids = Integer.min(peerCidLimit, MAX_CIDS_PER_CONNECTION);
    }
}
