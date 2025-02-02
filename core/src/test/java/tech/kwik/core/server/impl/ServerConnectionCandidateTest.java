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
package tech.kwik.core.server.impl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.agent15.engine.TlsServerEngineFactory;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.crypto.CryptoStream;
import tech.kwik.core.frame.CryptoFrame;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.TestUtils;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.InitialPacket;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.send.SenderImpl;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnectionFactory;
import tech.kwik.core.server.ServerConnectionRegistry;
import tech.kwik.core.test.FieldReader;
import tech.kwik.core.test.TestClock;
import tech.kwik.core.test.TestScheduledExecutor;
import tech.kwik.core.tls.ClientHelloBuilder;

import java.io.InputStream;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
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
    private ServerConnectionRegistry connectionRegistry;
    private InetSocketAddress clientAddress;
    private byte[] scid;
    private byte[] odcid;
    private Version version = Version.getDefault();

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
        connectionRegistry = mock(ServerConnectionRegistry.class);
        clientAddress = new InetSocketAddress("localhost", 55333);
        scid = new byte[0];
        odcid = new byte[8];
    }

    @Test
    void firstInitialPacketShouldSetAntiAmplificationLimit() throws Exception {
        // Given
        byte[] initialPacketBytes = TestUtils.createValidInitial(version);
        odcid = Arrays.copyOfRange(initialPacketBytes, 6, 6 + 8);
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, version, clientAddress, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(initialPacketBytes), clientAddress);
        testExecutor.check();

        // Then
        assertThat(createdServerConnection).isNotNull();
        Integer antiAmplificationLimit = (Integer) new FieldReader(createdServerConnection.getSender(), SenderImpl.class.getDeclaredField("antiAmplificationLimit")).read();
        assertThat(antiAmplificationLimit).isEqualTo(3 * 1200);
    }

    @Test
    void firstInitialCarriedInSmallDatagramShouldBeDiscarded() throws Exception {
        byte[] initialPacketBytes = TestUtils.createValidInitialNoPadding(version);
        odcid = Arrays.copyOfRange(initialPacketBytes, 6, 6 + 8);
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, version, clientAddress, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(initialPacketBytes), clientAddress);
        testExecutor.check();

        // Then
        assertThat(createdServerConnection).isNull();
        verify(connectionRegistry, never()).registerConnection(any(ServerConnectionProxy.class), any(byte[].class));
    }

    @Test
    void firstInitialWithPaddingInDatagramShouldCreateConnection() throws Exception {
        byte[] initialPacketBytes = TestUtils.createValidInitialNoPadding(version);
        odcid = Arrays.copyOfRange(initialPacketBytes, 6, 6 + 8);
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, version, clientAddress, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        ByteBuffer datagramBytes = ByteBuffer.allocate(1200);
        datagramBytes.put(initialPacketBytes);
        datagramBytes.rewind();
        connectionCandidate.parsePackets(0, Instant.now(), datagramBytes, clientAddress);
        testExecutor.check();

        // Then
        assertThat(createdServerConnection).isNotNull();
    }

    @Test
    void whenDatagramContainsCoalescedPacketsConnectionProxyShouldReceivedRemainingData() throws Exception {
        // Given
        byte[] initialPacketBytes = TestUtils.createValidInitial(version);
        odcid = Arrays.copyOfRange(initialPacketBytes, 6, 6 + 8);
        byte[] datagramData = new byte[1500];  // Simulating a second 300-byte packet in the same datagram.
        System.arraycopy(initialPacketBytes, 0, datagramData, 0, initialPacketBytes.length);
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, version, clientAddress, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(datagramData), clientAddress);
        testExecutor.check();

        // Then
        ByteBuffer remainingDatagramData = ((TestServerConnectionFactory) serverConnectionFactory).getRemainingDatagramData();
        assertThat(remainingDatagramData.position()).isEqualTo(1200);
        assertThat(remainingDatagramData.remaining()).isEqualTo(1500 - initialPacketBytes.length);
    }

    @Test
    void firstInitialPacketWithoutCryptoFrameShouldNotCreateConnection() throws Exception {
        // Given
        List<QuicFrame> frames = List.of(new PingFrame(), new Padding(1164));
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, version, clientAddress, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        byte data[] = createInitialPacketBytes(scid, odcid, frames);
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(data), clientAddress);
        testExecutor.check();

        // Then
        assertThat(createdServerConnection).isNull();
    }

    @Test
    void firstInitialPacketWithoutCompleteClientHelloShouldNotCreateConnection() throws Exception {
        // Given
        byte[] firstHalfOfClientHello = new byte[1165];
        ByteBuffer.wrap(firstHalfOfClientHello).putInt(0x010007d0); // 0x01 = handshake, 0x0007d0 = length (2000 bytes)
        CryptoFrame firstCryptoFrame = new CryptoFrame(version, firstHalfOfClientHello);
        List<QuicFrame> frames = List.of(firstCryptoFrame);
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, version, clientAddress, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        byte data[] = createInitialPacketBytes(scid, odcid, frames);
        assertThat(data.length).isGreaterThanOrEqualTo(1200);
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(data), clientAddress);
        testExecutor.check();

        // Then
        assertThat(createdServerConnection).isNull();
    }

    @Test
    void whenClientHelloIsSplitOverTwoPacketsThenLastPacketShouldCreateConnection()  throws Exception {
        // Given
        CryptoFrame[] cryptoFrames = createSplitClientHelloCryptoFrames();
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, version, clientAddress, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        byte datagram1[] = createInitialPacketBytes(scid, odcid, List.of(cryptoFrames[0], new Padding(1200 - cryptoFrames[0].getFrameLength())));
        assertThat(datagram1.length).isGreaterThanOrEqualTo(1200);
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(datagram1), clientAddress);
        testExecutor.check();
        assertThat(createdServerConnection).isNull();
        byte datagram2[] = createInitialPacketBytes(scid, odcid, List.of(cryptoFrames[1], new Padding(1200 - cryptoFrames[1].getFrameLength())));
        assertThat(datagram2.length).isGreaterThanOrEqualTo(1200);
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(datagram2), clientAddress);
        testExecutor.check();

        // Then
        assertThat(createdServerConnection).isNotNull();
    }

    @Test
    void whenClientHelloIsSplitOverMultiplePacketsConnectionProxyShouldReceiveCoalescedPacketsInLastDatagram() throws Exception {
        // Given
        CryptoFrame[] cryptoFrames = createSplitClientHelloCryptoFrames();

        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, version, clientAddress, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        byte[] datagram1 = createInitialPacketBytes(scid, odcid, List.of(cryptoFrames[0], new Padding(1200 - cryptoFrames[0].getFrameLength())));
        assertThat(datagram1.length).isGreaterThanOrEqualTo(1200);
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(datagram1), clientAddress);
        testExecutor.check();
        assertThat(createdServerConnection).isNull();

        byte[] initial2 = createInitialPacketBytes(scid, odcid, List.of(cryptoFrames[1]));
        byte[] coalesced = new byte[1200 - initial2.length];
        for (int i = 0; i < coalesced.length; i++) {
            coalesced[i] = (byte) i;
        }
        byte[] datagram2 = new byte[1200];
        System.arraycopy(initial2, 0, datagram2, 0, initial2.length);
        System.arraycopy(coalesced, 0, datagram2, initial2.length, coalesced.length);
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(datagram2), clientAddress);
        testExecutor.check();

        // Then
        ByteBuffer remainingDatagramData = ((TestServerConnectionFactory) serverConnectionFactory).getRemainingDatagramData();
        assertThat(remainingDatagramData.position()).isEqualTo(initial2.length);
        assertThat(remainingDatagramData.remaining()).isEqualTo(1200 - initial2.length);
        assertThat(remainingDatagramData.get()).isEqualTo((byte) 0);
        assertThat(remainingDatagramData.get()).isEqualTo((byte) 1);
        assertThat(remainingDatagramData.get()).isEqualTo((byte) 2);
        assertThat(remainingDatagramData.get()).isEqualTo((byte) 3);
    }

    @Test
    void whenInitialPacketsHaveDifferentSourceAddressAllButTheFirstShouldBeIgnored()  throws Exception {
        // Given
        CryptoFrame[] cryptoFrames = createSplitClientHelloCryptoFrames();

        InetSocketAddress address1 = new InetSocketAddress("localhost", 55333);
        InetSocketAddress address2 = new InetSocketAddress("localhost", 41975);
        ServerConnectionCandidate connectionCandidate = new ServerConnectionCandidate(context, version, address1, scid, odcid, serverConnectionFactory, connectionRegistry, logger);

        // When
        byte datagram1[] = createInitialPacketBytes(scid, odcid, List.of(cryptoFrames[0], new Padding(1200 - cryptoFrames[0].getFrameLength())));
        assertThat(datagram1.length).isGreaterThanOrEqualTo(1200);
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(datagram1), address1);
        testExecutor.check();
        assertThat(createdServerConnection).isNull();
        byte datagram2[] = createInitialPacketBytes(scid, odcid, List.of(cryptoFrames[1], new Padding(1200 - cryptoFrames[1].getFrameLength())));
        assertThat(datagram2.length).isGreaterThanOrEqualTo(1200);
        connectionCandidate.parsePackets(0, Instant.now(), ByteBuffer.wrap(datagram2), address2);
        testExecutor.check();

        // Then
        assertThat(createdServerConnection).isNull();
    }

    byte[] createInitialPacketBytes(byte[] scid, byte[] odcid, List<QuicFrame> frames) throws Exception {
        InitialPacket initialPacket = new InitialPacket(version, scid, odcid, null, frames);
        initialPacket.setPacketNumber(0);
        ConnectionSecrets secrets = new ConnectionSecrets(VersionHolder.with(version), Role.Client, null, mock(Logger.class));
        secrets.computeInitialKeys(odcid);
        return initialPacket.generatePacketBytes(secrets.getOwnAead(EncryptionLevel.Initial));
    }

    private CryptoFrame[] createSplitClientHelloCryptoFrames() {
        byte[] validClientHelloBytes = new ClientHelloBuilder().buildBinary();
        int firstHalfLength = validClientHelloBytes.length / 2;
        CryptoFrame frame1 = new CryptoFrame(version, 0, Arrays.copyOfRange(validClientHelloBytes, 0, firstHalfLength));
        CryptoFrame frame2 = new CryptoFrame(version, firstHalfLength, Arrays.copyOfRange(validClientHelloBytes, firstHalfLength, validClientHelloBytes.length));
        return new CryptoFrame[] {frame1, frame2};
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
        public ServerConnectionImpl createNewConnection(Version version, InetSocketAddress clientAddress, byte[] originalScid, byte[] originalDcid, CryptoStream cryptoStream) {
            ServerConnectionImpl newConnection = super.createNewConnection(version, clientAddress, originalScid, originalDcid, cryptoStream);
            createdServerConnection = newConnection;
            return newConnection;
        }

        @Override
        public ServerConnectionProxy createServerConnectionProxy(ServerConnectionImpl connection, List<InitialPacket> initialPackets, ByteBuffer data, PacketMetaData metaData) {
            remainingDatagramData = data;
            return new ServerConnectionThreadDummy(connection, initialPackets.get(0), metaData);
        }

        public ByteBuffer getRemainingDatagramData() {
            return remainingDatagramData;
        }
    }
}