/*
 * Copyright © 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.agent15.engine.ServerMessageSender;
import tech.kwik.agent15.engine.TlsServerEngine;
import tech.kwik.agent15.engine.TlsServerEngineFactory;
import tech.kwik.agent15.engine.TlsStatusEventHandler;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.server.impl.ServerConnectionImpl;

import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


class ServerConnectionFactoryTest {

    private TlsServerEngineFactory tlsServerEngineFactory;
    private InetSocketAddress someClient;

    @BeforeEach()
    void initTlsServerEngineFactory() {
        tlsServerEngineFactory = mock(TlsServerEngineFactory.class);
        when(tlsServerEngineFactory.createServerEngine(any(ServerMessageSender.class), any(TlsStatusEventHandler.class))).thenReturn(mock(TlsServerEngine.class));
        someClient = new InetSocketAddress("10.0.0.10", 32942);
    }

    @Test
    void newConnectionHasRandomSourceConnectionId() {
        ServerConnectionFactory connectionFactory = new ServerConnectionFactory(null, tlsServerEngineFactory, getConfig(16), null, null, cid -> {}, mock(Logger.class));
        ServerConnectionImpl conn1 = connectionFactory.createNewConnection(Version.getDefault(), someClient, new byte[8], new byte[8], null);
        ServerConnectionImpl conn2 = connectionFactory.createNewConnection(Version.getDefault(), someClient, new byte[8], new byte[8], null);

        assertThat(conn1.getSourceConnectionId()).hasSize(16);
        assertThat(conn2.getSourceConnectionId()).hasSize(16);
        assertThat(conn1.getSourceConnectionId()).isNotEqualTo(conn2.getSourceConnectionId());
    }

    @Test
    void connectionFactorySupportsConnectionIdsWithSmallLength() {
        ServerConnectionFactory connectionFactory = new ServerConnectionFactory(null, tlsServerEngineFactory, getConfig(4), null, null, cid -> {}, mock(Logger.class));
        ServerConnectionImpl conn1 = connectionFactory.createNewConnection(Version.getDefault(), someClient, new byte[8], new byte[8], null);
        assertThat(conn1.getSourceConnectionId()).hasSize(4);
    }

    @Test
    void connectionFactorySupportsConnectionIdsWithLargeLength() {
        ServerConnectionFactory connectionFactory = new ServerConnectionFactory(null, tlsServerEngineFactory, getConfig(20), null, null, cid -> {}, mock(Logger.class));
        ServerConnectionImpl conn1 = connectionFactory.createNewConnection(Version.getDefault(), someClient, new byte[8], new byte[8], null);
        assertThat(conn1.getSourceConnectionId()).hasSize(20);
    }

    @Test
    void connectionFactoryWillNotAcceptConnectionLengthLargerThan20() {
        assertThatThrownBy(() ->
                new ServerConnectionFactory(null, tlsServerEngineFactory, getConfig(21), null, null, cid -> {}, mock(Logger.class))
        ).isInstanceOf(IllegalArgumentException.class);
    }

    ServerConnectionConfig getConfig(int connectionIdLength) {
        ServerConnectionConfig config = mock(ServerConnectionConfig.class);
        when(config.connectionIdLength()).thenReturn(connectionIdLength);
        return config;
    }

}