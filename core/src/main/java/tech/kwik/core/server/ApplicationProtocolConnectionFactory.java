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
package tech.kwik.core.server;

import tech.kwik.core.QuicConnection;

/**
 * Factory for ApplicationProtocolConnection objects.
 */
public interface ApplicationProtocolConnectionFactory extends ApplicationProtocolSettings {

    /**
     * Create a new connection for the given protocol.
     * If, for some reason, the application protocol connection cannot be created, this method may
     * return {@code null}, but in that case it <i>must</i> close the underlying QUIC connection.
     * @param protocol
     * @param quicConnection
     * @return
     */
    ApplicationProtocolConnection createConnection(String protocol, QuicConnection quicConnection);
}
