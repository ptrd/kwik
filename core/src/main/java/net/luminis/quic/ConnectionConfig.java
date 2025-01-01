/*
 * Copyright © 2023, 2024, 2025 Peter Doornbosch
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
package net.luminis.quic;

public interface ConnectionConfig {

    /**
     * @return  the maximum idle time in milliseconds before the connection is closed.
     */
    int maxIdleTimeout();

    /**
     * @return  the maximum number of concurrent unidirectional streams that can be opened by the peer.
     */
    int maxOpenPeerInitiatedUnidirectionalStreams();

    /**
     * @return the total number of unidirectional streams that the peer can open during the lifetime of the connection.
     */
    long maxTotalPeerInitiatedUnidirectionalStreams();

    /**
     * @return  the maximum number of concurrent bidirectional streams that can be opened by the peer.
     */
    int maxOpenPeerInitiatedBidirectionalStreams();

    /**
     * @return  the total number of bidirectional streams that the peer can open during the lifetime of the connection.
     */
    long maxTotalPeerInitiatedBidirectionalStreams();

    /**
     * @return  the maximum buffer size on connection level (shared by all streams).
     */
    long maxConnectionBufferSize();

    /**
     * @return  the maximum buffer size on stream level (per stream) for unidirectional streams.
     */
    long maxUnidirectionalStreamBufferSize();

    /**
     * @return  the maximum buffer size on stream level (per stream) for bidirectional streams.
     */
    long maxBidirectionalStreamBufferSize();

    /**
     * @return whether to apply the strict interpretation of RFC-9000 with respect to the smallest allowed maximum datagram size.
     */
    boolean useStrictSmallestAllowedMaximumDatagramSize();
}
