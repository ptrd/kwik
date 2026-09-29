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
package tech.kwik.core;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.server.ApplicationProtocolConnection;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;
import tech.kwik.core.test.UdpRelay;

import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end test of client-initiated connection migration, over real UDP sockets on the loopback interface.
 */
class ConnectionMigrationTest {

    private static final String MIGRATION_PROPERTY = "tech.kwik.server.connection-migration.enabled";

    private final Logger log = debugLogger();
    private static Logger debugLogger() { tech.kwik.core.log.SysOutLogger l = new tech.kwik.core.log.SysOutLogger(); l.logInfo(true); l.logWarning(true); return l; }
    private ServerConnector serverConnector;
    private DatagramSocket serverSocket;
    private UdpRelay relay;
    private QuicClientConnection client;

    @BeforeEach
    void startServer() throws Exception {
        System.setProperty(MIGRATION_PROPERTY, "true");
        // Wildcard, like the client sockets and the relay (see UdpRelay)
        serverSocket = new DatagramSocket(0);
        InputStream certificate = getClass().getResourceAsStream("server/impl/localhost.pem");
        InputStream privateKey = getClass().getResourceAsStream("server/impl/localhost.key");
        serverConnector = ServerConnector.builder()
                .withSocket(serverSocket)
                .withCertificate(certificate, privateKey)
                .withConfiguration(ServerConnectionConfig.builder()
                        .maxOpenPeerInitiatedBidirectionalStreams(10)
                        .build())
                .withLogger(log)
                .build();
        serverConnector.registerApplicationProtocol("echo", new EchoFactory());
        serverConnector.start();
        relay = new UdpRelay(new InetSocketAddress(InetAddress.getLoopbackAddress(), serverSocket.getLocalPort()));
    }

    @AfterEach
    void stop() {
        System.clearProperty(MIGRATION_PROPERTY);
        if (client != null) {
            client.close();
        }
        if (relay != null) {
            relay.close();
        }
        if (serverConnector != null) {
            serverConnector.close();
        }
    }

    @Test
    @Timeout(30)
    void clientMigratesAwayFromBlackholedPathAndConnectionContinues() throws Exception {
        client = connect();
        assertThat(echo("before")).isEqualTo("before");

        for (int i = 1; i <= 3; i++) {
            int oldPort = client.getLocalAddress().getPort();
            relay.blackhole(oldPort);

            assertThat(migrate(Duration.ofSeconds(5))).isTrue();

            assertThat(client.getLocalAddress().getPort()).isNotEqualTo(oldPort);
            assertThat(echo("after migration " + i)).isEqualTo("after migration " + i);
        }
        assertThat(relay.getFlowCount()).isEqualTo(4);
    }

    @Test
    @Timeout(30)
    void migrationIsRefusedWhenServerDisablesActiveMigration() throws Exception {
        System.clearProperty(MIGRATION_PROPERTY);
        client = connect();
        // A round trip ensures the handshake is confirmed, so it is really the server's transport parameter that is tested
        assertThat(echo("before")).isEqualTo("before");
        int port = client.getLocalAddress().getPort();

        assertThat(client.migrate(Duration.ofSeconds(1))).isFalse();

        assertThat(client.getLocalAddress().getPort()).isEqualTo(port);
        assertThat(echo("still working")).isEqualTo("still working");
    }

    /**
     * Migrates, retrying while the connection has no unused peer connection ID yet: the server replaces a retired one
     * only a round trip after the retirement, which on loopback is easily outrun by back-to-back migrations.
     */
    private boolean migrate(Duration timeout) throws Exception {
        long deadline = System.currentTimeMillis() + timeout.toMillis();
        while (true) {
            if (client.migrate(Duration.ofSeconds(1))) {
                return true;
            }
            if (System.currentTimeMillis() > deadline) {
                return false;
            }
            Thread.sleep(50);
        }
    }

    private QuicClientConnection connect() throws Exception {
        InetSocketAddress relayAddress = relay.getAddress();
        QuicClientConnection connection = QuicClientConnection.newBuilder()
                .uri(URI.create("echo://" + relayAddress.getAddress().getHostAddress() + ":" + relayAddress.getPort()))
                .applicationProtocol("echo")
                .noServerCertificateCheck()
                .logger(log)
                .build();
        connection.connect();
        return connection;
    }

    private String echo(String message) throws IOException {
        QuicStream stream = client.createStream(true);
        stream.getOutputStream().write(message.getBytes(StandardCharsets.UTF_8));
        stream.getOutputStream().close();
        return new String(stream.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static class EchoFactory implements ApplicationProtocolConnectionFactory {

        @Override
        public ApplicationProtocolConnection createConnection(String protocol, QuicConnection quicConnection) {
            return new ApplicationProtocolConnection() {
                @Override
                public void acceptPeerInitiatedStream(QuicStream stream) {
                    new Thread(() -> {
                        try {
                            byte[] data = stream.getInputStream().readAllBytes();
                            stream.getOutputStream().write(data);
                            stream.getOutputStream().close();
                        }
                        catch (IOException e) {
                            // test will fail on missing echo
                        }
                    }).start();
                }
            };
        }

        @Override
        public int maxConcurrentPeerInitiatedUnidirectionalStreams() {
            return 0;
        }

        @Override
        public int maxConcurrentPeerInitiatedBidirectionalStreams() {
            return 10;
        }
    }
}
