/*
 * Copyright © 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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

import net.luminis.quic.QuicConnection;

import java.util.*;

/**
 * Registers supported application protocols.
 */
public class ApplicationProtocolRegistry {

    Map<String, ApplicationProtocolConnectionFactory> registeredFactories = new LinkedHashMap<>();

    /**
     * Select the (server preferred) protocol, given the list of clientProtocols that the client supports.
     * @param clientProtocols  list of protocols (alpn's) the client advertises
     * @return  selected protocol (if any)
     */
    Optional<String> selectSupportedApplicationProtocol(List<String> clientProtocols) {
        Set<String> intersection = new LinkedHashSet<>(registeredFactories.keySet());
        intersection.retainAll(clientProtocols);
        return intersection.stream().findFirst();
    }

    /**
     * Creates an application protocol connection for the given protocol on top of the given QUIC connection.
     * @param protocol  protocol alpn
     * @param quicConnection  underlying QUIC connection
     * @return application protocol instance
     */
    ApplicationProtocolConnection startApplicationProtocolConnection(String protocol, QuicConnection quicConnection) {
        ApplicationProtocolConnection applicationProtocolConnection = registeredFactories.get(protocol).createConnection(protocol, quicConnection);
        quicConnection.setPeerInitiatedStreamCallback(applicationProtocolConnection::acceptPeerInitiatedStream);
        return applicationProtocolConnection;
    }

    ApplicationProtocolConnectionFactory getApplicationProtocolConnectionFactory(String protocol) {
        return registeredFactories.get(protocol);
    }

    /**
     * Add a protocol with lower preference than the protocols already added.
     * So, to set protocols in order of preference, start with adding the most preferred, etc.
     *
     * @param protocol  the protocol alpn
     * @param factory   factory for creating connections for the given protocol
     */
    void registerApplicationProtocol(String protocol, ApplicationProtocolConnectionFactory factory) {
        registeredFactories.put(protocol, factory);
    }

    /**
     * Returns the list of APLN's registered.
     * @return  list of APLN's
     */
    Set<String> getRegisteredApplicationProtocols() {
        return registeredFactories.keySet();
    }
}
