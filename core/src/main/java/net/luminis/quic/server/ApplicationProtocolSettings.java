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
package net.luminis.quic.server;

public interface ApplicationProtocolSettings {

    int NOT_SPECIFIED = -1;

    /**
     * The maximum number of concurrent unidirectional streams that the peer may initiate.
     * This method should be overridden to return a non-null value; future versions of Kwik might enforce this.
     *
     * @return the maximum number of concurrent unidirectional streams that the peer may initiate.
     */
    default int maxConcurrentPeerInitiatedUnidirectionalStreams() { return NOT_SPECIFIED; }

    /**
     * The total number of unidirectional streams that the peer may initiate during the lifetime of the connection.
     * @return
     */
    default long maxTotalPeerInitiatedUnidirectionalStreams() { return Long.MAX_VALUE; }

    /**
     * The maximum number of concurrent bidirectional streams that the peer may initiate.
     * This method should be overridden to return a non-null value; future versions of Kwik might enforce this.
     *
     * @return
     */
    default int maxConcurrentPeerInitiatedBidirectionalStreams() { return NOT_SPECIFIED; }

    /**
     * The total number of bidirectional streams that the peer may initiate during the lifetime of the connection.
     * @return
     */
    default long maxTotalPeerInitiatedBidirectionalStreams() { return Long.MAX_VALUE; }

    /**
     * The minimum receive buffer size that this peer will use for unidirectional streams.
     * @return
     */
    default int minUnidirectionalStreamReceiverBufferSize() { return 5 * 1024; }

    /**
     * The maximum receive buffer size that this peer will use for unidirectional streams.
     * @return
     */
    default long maxUnidirectionalStreamReceiverBufferSize() { return Long.MAX_VALUE; }

    /**
     * The minimum receive buffer size that this peer will use for bidirectional streams.
     * @return
     */
    default int minBidirectionalStreamReceiverBufferSize() { return 5 * 1024; }

    /**
     * The maximum receive buffer size that this peer will use for bidirectional streams.
     * @return
     */
    default long maxBidirectionalStreamReceiverBufferSize() { return Long.MAX_VALUE; }

    /**
     * Whether the application protocol requires the Datagram extension (RFC 9221) to be enabled.
     * @return
     */
    default boolean enableDatagramExtension() { return false; }
}
