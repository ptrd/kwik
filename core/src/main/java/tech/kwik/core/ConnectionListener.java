/*
 * Copyright © 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.core;

/**
 * Listener for connection events like connect and disconnect events.
 * Primary use case is to be notified when a connection is terminated and obtain the reason why, including the error
 * code (if any).
 */
public interface ConnectionListener {

    default void connected(ConnectionEstablishedEvent connectionEstablishedEvent) {};

    /**
     * Called (client connections only) each time a probe timeout occurs after the handshake is confirmed, which
     * indicates the connection might be stalled. As the probe timeout is derived from the RTT, this is a
     * path-independent indication that the network path currently used has stopped delivering packets: an application
     * can use it to decide to migrate the connection (see {@link QuicClientConnection#migrate(java.time.Duration)}).
     * Use the probe timeout count or stalled duration of the event to determine how severe the stall is.
     * @param connectionStalledEvent
     */
    default void stalled(ConnectionStalledEvent connectionStalledEvent) {};

    void disconnected(ConnectionTerminatedEvent connectionTerminatedEvent);
}
