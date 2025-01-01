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
package net.luminis.quic.server.impl;

import net.luminis.quic.impl.TestUtils;
import net.luminis.quic.impl.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.PacketMetaData;
import net.luminis.quic.send.SenderImpl;
import net.luminis.quic.server.ServerConnectionConfig;
import net.luminis.quic.server.ServerConnectionFactory;
import net.luminis.quic.server.ServerConnectionRegistry;
import net.luminis.quic.test.FieldReader;
import net.luminis.quic.test.TestClock;
import net.luminis.quic.test.TestScheduledExecutor;
import net.luminis.tls.engine.TlsServerEngineFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
    private TestClock clock;
    private ServerConnectionImpl createdServerConnection;
    private ServerConnectionFactory serverConnectionFactory;
    private Context context;
    private TestScheduledExecutor testExecutor;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        logger = mock(Logger.class);
        clock = new TestClock();
        InputStream certificate = getClass().getResourceAsStream("localhost.pem");
        InputStream privateKey = getClass().getResourceAsStream("localhost.key");
        TlsServerEngineFactory tlsServerEngineFactory = new TlsServerEngineFactory(certificate, privateKey);
        serverConnectionFactory = new TestServerConnectionFactory(16, mock(DatagramSocket.class), tlsServerEngineFactory,
                false, mock(ApplicationProtocolRegistry.class), 100, cid -> {}, logger);
        context = mock(Context.class);
        testExecutor = new TestScheduledExecutor(clock);
        when(context.getSharedServerExecutor()).thenReturn(testExecutor);
        when(context.getSharedScheduledExecutor()).thenReturn(testExecutor);
    }

    @Test
    void firstInitialPacketShouldSetAntiAmplificationLimit() throws Exception {
        // Given
        byte[] initialPacketBytes = TestUtils.createValidInitial(Version.getDefault());
        byte[] scid = new byte[0];
        byte[] odcid = Arrays.copyOfRange(initialPacketBytes, 6, 6 + 8);
        ServerConnectionRegistry connectionRegistry = mock(ServerConnectionRegistry.class);
        InetSocketAddress address = new InetSocketAddress("localhost", 55333);
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, Version.getDefault(), address, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(initialPacketBytes), null);
        testExecutor.check();

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
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, Version.getDefault(), address, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(initialPacketBytes), null);
        testExecutor.check();

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
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, Version.getDefault(), address, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        ByteBuffer datagramBytes = ByteBuffer.allocate(1200);
        datagramBytes.put(initialPacketBytes);
        datagramBytes.rewind();
        connectionCandidate.parsePackets(0, Instant.now(), datagramBytes, null);
        testExecutor.check();

        // Then
        assertThat(createdServerConnection).isNotNull();
    }

    @Test
    void whenDatagramContainsCoalescedPacketsConnectionProxyShouldReceivedRemainingData() throws Exception {
        // Given
        byte[] initialPacketBytes = TestUtils.createValidInitial(Version.getDefault());
        byte[] scid = new byte[0];
        byte[] odcid = Arrays.copyOfRange(initialPacketBytes, 6, 6 + 8);
        byte[] datagramData = new byte[1500];  // Simulating a second 300-byte packet in the same datagram.
        System.arraycopy(initialPacketBytes, 0, datagramData, 0, initialPacketBytes.length);
        ServerConnectionRegistry connectionRegistry = mock(ServerConnectionRegistry.class);
        InetSocketAddress address = new InetSocketAddress("localhost", 55333);
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, Version.getDefault(), address, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(datagramData), null);
        testExecutor.check();

        // Then
        ByteBuffer remainingDatagramData = ((TestServerConnectionFactory) serverConnectionFactory).getRemainingDatagramData();
        assertThat(remainingDatagramData.position()).isEqualTo(1200);
        assertThat(remainingDatagramData.remaining()).isEqualTo(1500 - initialPacketBytes.length);
    }

    static ServerConnectionConfig getDefaultConfiguration(int connectionIdLength) {
        return ServerConnectionConfig.builder()
                .maxIdleTimeoutInSeconds(30)
                .maxUnidirectionalStreamBufferSize(1_000_000)
                .maxBidirectionalStreamBufferSize(1_000_000)
                .maxConnectionBufferSize(10_000_000)
                .maxOpenPeerInitiatedUnidirectionalStreams(10)
                .maxOpenPeerInitiatedBidirectionalStreams(100)
                .connectionIdLength(connectionIdLength)
                .build();
    }

    class TestServerConnectionFactory extends ServerConnectionFactory {
        private ByteBuffer remainingDatagramData;

        public TestServerConnectionFactory(int connectionIdLength, DatagramSocket serverSocket, TlsServerEngineFactory tlsServerEngineFactory, boolean requireRetry, ApplicationProtocolRegistry applicationProtocolRegistry, int initalRtt, Consumer<ServerConnectionImpl> closeCallback, Logger log) {
            super(serverSocket, tlsServerEngineFactory, getDefaultConfiguration(connectionIdLength), applicationProtocolRegistry, null, closeCallback, log);
        }

        @Override
        public ServerConnectionImpl createNewConnection(Version version, InetSocketAddress clientAddress, byte[] originalScid, byte[] originalDcid) {
            ServerConnectionImpl newConnection = super.createNewConnection(version, clientAddress, originalScid, originalDcid);
            createdServerConnection = newConnection;
            return newConnection;
        }

        @Override
        public ServerConnectionProxy createServerConnectionProxy(ServerConnectionImpl connection, InitialPacket initialPacket, ByteBuffer data, PacketMetaData metaData) {
            remainingDatagramData = data;
            return new ServerConnectionThreadDummy(connection, initialPacket, metaData);
        }

        public ByteBuffer getRemainingDatagramData() {
            return remainingDatagramData;
        }
    }
}