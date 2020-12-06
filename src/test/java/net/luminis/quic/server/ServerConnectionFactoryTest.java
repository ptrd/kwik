package net.luminis.quic.server;

import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.tls.handshake.TlsServerEngineFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;


class ServerConnectionFactoryTest {

    private TlsServerEngineFactory tlsServerEngineFactory;

    @BeforeEach()
    void initTlsServerEngineFactory() {
        tlsServerEngineFactory = mock(TlsServerEngineFactory.class);
    }

    @Test
    void newConnectionHasRandomSourceConnectionId() {
        ServerConnectionFactory connectionFactory = new ServerConnectionFactory(16, null, tlsServerEngineFactory, null, 100, cid -> {}, mock(Logger.class));
        ServerConnection conn1 = connectionFactory.createNewConnection(Version.getDefault(), null, new byte[8], new byte[8]);
        ServerConnection conn2 = connectionFactory.createNewConnection(Version.getDefault(), null, new byte[8], new byte[8]);

        assertThat(conn1.getSourceConnectionId()).hasSize(16);
        assertThat(conn2.getSourceConnectionId()).hasSize(16);
        assertThat(conn1.getSourceConnectionId()).isNotEqualTo(conn2.getSourceConnectionId());
    }

    @Test
    void connectionFactorySupportsConnectionIdsWithSmallLength() {
        ServerConnectionFactory connectionFactory = new ServerConnectionFactory(4, null, tlsServerEngineFactory, null, 100, cid -> {}, mock(Logger.class));
        ServerConnection conn1 = connectionFactory.createNewConnection(Version.getDefault(), null, new byte[8], new byte[8]);
        assertThat(conn1.getSourceConnectionId()).hasSize(4);
    }

    @Test
    void connectionFactorySupportsConnectionIdsWithLargeLength() {
        ServerConnectionFactory connectionFactory = new ServerConnectionFactory(20, null, tlsServerEngineFactory, null, 100, cid -> {}, mock(Logger.class));
        ServerConnection conn1 = connectionFactory.createNewConnection(Version.getDefault(), null, new byte[8], new byte[8]);
        assertThat(conn1.getSourceConnectionId()).hasSize(20);
    }

    @Test
    void connectionFactoryWillNotAcceptConnectionLengthLargerThan20() {
        assertThatThrownBy(() ->
                new ServerConnectionFactory(21, null, tlsServerEngineFactory, null, 100, cid -> {}, mock(Logger.class))
        ).isInstanceOf(IllegalArgumentException.class);
    }


}