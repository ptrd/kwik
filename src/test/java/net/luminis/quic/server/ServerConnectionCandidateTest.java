/*
 * Copyright © 2021, 2022 Peter Doornbosch
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

import net.luminis.quic.TestUtils;
import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.send.SenderImpl;
import net.luminis.tls.handshake.TlsServerEngineFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.internal.util.reflection.FieldReader;

import java.io.InputStream;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;


class ServerConnectionCandidateTest {

    private Logger logger;
    private ServerConnectionImpl createdServerConnection;
    private ServerConnectionFactory serverConnectionFactory;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        logger = new SysOutLogger(); // mock(Logger.class);
        logger.logDebug(true);

        InputStream certificate = getClass().getResourceAsStream("localhost.pem");
        InputStream privateKey = getClass().getResourceAsStream("localhost.key");
        TlsServerEngineFactory tlsServerEngineFactory = new TlsServerEngineFactory(certificate, privateKey);
        serverConnectionFactory = new TestServerConnectionFactory(16, null, tlsServerEngineFactory, false, mock(ApplicationProtocolRegistry.class), 100, cid -> {}, logger);
    }

    @Test
    void firstInitialPacketShouldSetAntiAmplificationLimit() throws Exception {
        // Given
        byte[] initialPacketBytes = TestUtils.createValidInitial(Version.getDefault());
        byte[] scid = new byte[0];
        byte[] odcid = Arrays.copyOfRange(initialPacketBytes, 6, 6 + 8);
        ServerConnectionRegistry connectionRegistry = mock(ServerConnectionRegistry.class);
        InetSocketAddress address = new InetSocketAddress("localhost", 55333);
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(Version.getDefault(), address, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(initialPacketBytes));
        Thread.sleep(500);

        // Then
        assertThat(createdServerConnection).isNotNull();
        Integer antiAmplificationLimit = (Integer) new FieldReader(createdServerConnection.getSender(), SenderImpl.class.getDeclaredField("antiAmplificationLimit")).read();
        assertThat(antiAmplificationLimit).isEqualTo(3 * 1200);
    }

    @Test
    void firstInitialCarriedInSmallDatagramShouldBeDiscarded() throws Exception {
        byte[] initialPacketBytes = TestUtils.createValidInitialNoPadding(Version.getDefault());
        byte[] scid = new byte[0];
        byte[] odcid = Arrays.copyOfRange(initialPacketBytes, 6, 6 + 8);
        ServerConnectionRegistry connectionRegistry = mock(ServerConnectionRegistry.class);
        InetSocketAddress address = new InetSocketAddress("localhost", 55333);
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(Version.getDefault(), address, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(initialPacketBytes));
        Thread.sleep(500);

        // Then
        assertThat(createdServerConnection).isNull();
        verify(connectionRegistry, never()).registerConnection(any(ServerConnectionProxy.class), any(byte[].class));
    }

    @Test
    void firstInitialWithPaddingInDatagramShouldCreateConnection() throws Exception {
        byte[] initialPacketBytes = TestUtils.createValidInitialNoPadding(Version.getDefault());
        byte[] scid = new byte[0];
        byte[] odcid = Arrays.copyOfRange(initialPacketBytes, 6, 6 + 8);
        ServerConnectionRegistry connectionRegistry = mock(ServerConnectionRegistry.class);
        InetSocketAddress address = new InetSocketAddress("localhost", 55333);
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(Version.getDefault(), address, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        ByteBuffer datagramBytes = ByteBuffer.allocate(1200);
        datagramBytes.put(initialPacketBytes);
        datagramBytes.rewind();
        connectionCandidate.parsePackets(0, Instant.now(), datagramBytes);
        Thread.sleep(500);

        // Then
        assertThat(createdServerConnection).isNotNull();
    }

    class TestServerConnectionFactory extends ServerConnectionFactory {
        public TestServerConnectionFactory(int connectionIdLength, DatagramSocket serverSocket, TlsServerEngineFactory tlsServerEngineFactory, boolean requireRetry, ApplicationProtocolRegistry applicationProtocolRegistry, int initalRtt, Consumer<byte[]> closeCallback, Logger log) {
            super(connectionIdLength, serverSocket, tlsServerEngineFactory, requireRetry, applicationProtocolRegistry, initalRtt, null, closeCallback, log);
        }

        @Override
        public ServerConnectionImpl createNewConnection(Version version, InetSocketAddress clientAddress, byte[] originalScid, byte[] originalDcid) {
            ServerConnectionImpl newConnection = super.createNewConnection(version, clientAddress, originalScid, originalDcid);
            createdServerConnection = newConnection;
            return newConnection;
        }
    }
}