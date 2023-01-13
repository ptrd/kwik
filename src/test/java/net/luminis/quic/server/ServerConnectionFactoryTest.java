/*
 * Copyright © 2021, 2022, 2023 Peter Doornbosch
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

import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.tls.handshake.ServerMessageSender;
import net.luminis.tls.handshake.TlsServerEngine;
import net.luminis.tls.handshake.TlsServerEngineFactory;
import net.luminis.tls.handshake.TlsStatusEventHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


class ServerConnectionFactoryTest {

    private TlsServerEngineFactory tlsServerEngineFactory;

    @BeforeEach()
    void initTlsServerEngineFactory() {
        tlsServerEngineFactory = mock(TlsServerEngineFactory.class);
        when(tlsServerEngineFactory.createServerEngine(any(ServerMessageSender.class), any(TlsStatusEventHandler.class))).thenReturn(mock(TlsServerEngine.class));
    }

    @Test
    void newConnectionHasRandomSourceConnectionId() {
        ServerConnectionFactory connectionFactory = new ServerConnectionFactory(16, null, tlsServerEngineFactory, false, null, 100, null, cid -> {}, mock(Logger.class));
        ServerConnectionImpl conn1 = connectionFactory.createNewConnection(Version.getDefault(), null, new byte[8], new byte[8]);
        ServerConnectionImpl conn2 = connectionFactory.createNewConnection(Version.getDefault(), null, new byte[8], new byte[8]);

        assertThat(conn1.getSourceConnectionId()).hasSize(16);
        assertThat(conn2.getSourceConnectionId()).hasSize(16);
        assertThat(conn1.getSourceConnectionId()).isNotEqualTo(conn2.getSourceConnectionId());
    }

    @Test
    void connectionFactorySupportsConnectionIdsWithSmallLength() {
        ServerConnectionFactory connectionFactory = new ServerConnectionFactory(4, null, tlsServerEngineFactory, false, null, 100, null, cid -> {}, mock(Logger.class));
        ServerConnectionImpl conn1 = connectionFactory.createNewConnection(Version.getDefault(), null, new byte[8], new byte[8]);
        assertThat(conn1.getSourceConnectionId()).hasSize(4);
    }

    @Test
    void connectionFactorySupportsConnectionIdsWithLargeLength() {
        ServerConnectionFactory connectionFactory = new ServerConnectionFactory(20, null, tlsServerEngineFactory, false, null, 100, null, cid -> {}, mock(Logger.class));
        ServerConnectionImpl conn1 = connectionFactory.createNewConnection(Version.getDefault(), null, new byte[8], new byte[8]);
        assertThat(conn1.getSourceConnectionId()).hasSize(20);
    }

    @Test
    void connectionFactoryWillNotAcceptConnectionLengthLargerThan20() {
        assertThatThrownBy(() ->
                new ServerConnectionFactory(21, null, tlsServerEngineFactory, false, null, 100, null, cid -> {}, mock(Logger.class))
        ).isInstanceOf(IllegalArgumentException.class);
    }


}