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

import net.luminis.quic.log.Logger;
import net.luminis.quic.send.Sender;

/**
 * Manages the collections of connection ID's for the connection, both for this (side of the) connection and the peer's.
 */
public class ConnectionIdManager {

    private final int connectionIdLength;
    private final Sender sender;
    private final SourceConnectionIdRegistry cidRegistry;

    public ConnectionIdManager(int connectionIdLength, Sender sender, Logger log) {
        this.connectionIdLength = connectionIdLength;
        this.sender = sender;
        cidRegistry = new SourceConnectionIdRegistry(connectionIdLength, log);
    }

    public byte[] getCurrentConnectionId() {
        return cidRegistry.getCurrent();
    }
}
