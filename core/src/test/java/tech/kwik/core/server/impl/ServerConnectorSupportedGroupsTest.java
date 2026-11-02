/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.core.server.impl;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import tech.kwik.agent15.TlsConstants.NamedGroup;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicSessionTicket;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.server.ApplicationProtocolConnection;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static tech.kwik.agent15.TlsConstants.NamedGroup.*;

/**
 * Runs real handshakes over the loopback interface, as the restriction is enforced by the interplay of the connector,
 * the connection and the TLS engine.
 */
@Timeout(60)
class ServerConnectorSupportedGroupsTest {

    private static final String ALPN = "test-groups";

    private final List<AutoCloseable> resources = new ArrayList<>();
    private int port;

    @AfterEach
    void closeResources() throws Exception {
        for (AutoCloseable resource : resources) {
            resource.close();
        }
    }

    @Test
    void clientOfferingOnlyOtherGroupsFailsHandshake() throws Exception {
        startServer(secp384r1);

        assertThatThrownBy(() -> connect(List.of(secp256r1), null)).isInstanceOf(IOException.class);
    }

    @Test
    void clientOfferingAcceptedGroupConnects() throws Exception {
        startServer(secp384r1);

        connect(List.of(secp384r1), null);  // Throws when the handshake fails
    }

    @Test
    void clientWithKeyShareForOtherGroupConnectsThroughHelloRetryRequest() throws Exception {
        startServer(secp384r1);

        // The client only sends a key share for its first group.
        connect(List.of(secp256r1, secp384r1), null);  // Throws when the handshake fails
    }

    @Test
    void withoutRestrictionAllAvailableGroupsAreAccepted() throws Exception {
        startServer();

        connect(List.of(secp256r1), null);  // Throws when the handshake fails
        connect(List.of(x448), null);  // Throws when the handshake fails
    }

    @Test
    void sessionResumptionDoesNotBypassRestriction() throws Exception {
        startServer(x25519);
        QuicClientConnection first = connect(List.of(x25519), null);
        QuicSessionTicket ticket = awaitSessionTicket(first);

        connect(List.of(x25519), ticket);  // Throws when the handshake fails
        assertThatThrownBy(() -> connect(List.of(secp256r1), ticket)).isInstanceOf(IOException.class);
    }

    @Test
    void emptyListIsRejected() {
        // An empty list would mean "accept all groups" for the TLS engine.
        assertThatThrownBy(() -> ServerConnector.builder().withSupportedGroups(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void duplicatesAreRejected() {
        assertThatThrownBy(() -> ServerConnector.builder().withSupportedGroups(List.of(x25519, x25519)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void groupThatIsNotAvailableFailsBuildWithoutBindingPort() throws Exception {
        // Depends on agent15-pqc not being on the test class path, which also holds for older JVMs that cannot load it.
        int freePort;
        try (DatagramSocket probe = new DatagramSocket(0)) {
            freePort = probe.getLocalPort();
        }

        assertThatThrownBy(() -> builder().withPort(freePort).withSupportedGroups(List.of(x25519, X25519MLKEM768)).build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("X25519MLKEM768")
                .hasMessageContaining("agent15-pqc");

        new DatagramSocket(freePort).close();  // Throws when the port was left bound
    }

    private ServerConnector.Builder builder() {
        return ServerConnector.builder()
                .withCertificate(getClass().getResourceAsStream("localhost.pem"), getClass().getResourceAsStream("localhost.key"))
                .withConfiguration(ServerConnectionConfig.builder()
                        .maxIdleTimeoutInSeconds(10)
                        .maxOpenPeerInitiatedBidirectionalStreams(10)
                        .maxOpenPeerInitiatedUnidirectionalStreams(0)
                        .build())
                .withLogger(new NullLogger());
    }

    private void startServer(NamedGroup... groups) throws Exception {
        DatagramSocket socket = new DatagramSocket(0);
        port = socket.getLocalPort();
        ServerConnector.Builder builder = builder().withSocket(socket);
        if (groups.length > 0) {
            builder.withSupportedGroups(List.of(groups));
        }
        ServerConnector server = builder.build();
        server.registerApplicationProtocol(ALPN, (ApplicationProtocolConnectionFactory) (protocol, connection) -> new ApplicationProtocolConnection() {});
        server.start();
        resources.add(0, () -> ((ServerConnectorImpl) server).close(Duration.ofMillis(100)));
    }

    private QuicClientConnection connect(List<NamedGroup> groups, QuicSessionTicket ticket) throws Exception {
        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder()
                .uri(URI.create("https://localhost:" + port))
                .applicationProtocol(ALPN)
                .noServerCertificateCheck()
                .connectTimeout(Duration.ofSeconds(5))
                .supportedGroups(groups);
        if (ticket != null) {
            builder.sessionTicket(ticket);
        }
        QuicClientConnection connection = builder.build();
        resources.add(0, connection::close);
        connection.connect();
        return connection;
    }

    private QuicSessionTicket awaitSessionTicket(QuicClientConnection connection) throws InterruptedException {
        while (connection.getNewSessionTickets().isEmpty()) {
            Thread.sleep(10);
        }
        return connection.getNewSessionTickets().get(0);
    }
}
