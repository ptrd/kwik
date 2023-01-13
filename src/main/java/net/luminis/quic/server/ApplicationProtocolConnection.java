/*
 * Copyright © 2020, 2021, 2022, 2023 Peter Doornbosch
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
package net.luminis.quic.server;

import net.luminis.quic.QuicStream;


/**
 * Represents an application protocol connection, running over an underlying QUIC connection.
 * Whether the instance has access to the underlying QUIC connection is up to the concrete implementation and depends
 * on how the instance is created in the ApplicationProtocolConnectionFactory.
 *
 * @see ApplicationProtocolConnectionFactory
 */
public interface ApplicationProtocolConnection {

    /**
     * Accept a newly created QUIC stream, whose creation is initiated by the peer.
     * Implementations that want to support (and do something useful with) peer-initiated streams, should override this method.
     *
     * @param stream  the newly created, peer initiated, stream
     */
    default void acceptPeerInitiatedStream(QuicStream stream) {}
}
