/*
 * Copyright © 2020. 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicConstants;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.frame.ConnectionCloseFrame;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.SysOutLogger;
import tech.kwik.core.packet.InitialPacket;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.packet.VersionNegotiationPacket;
import tech.kwik.core.receive.RawPacket;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionFactory;
import tech.kwik.core.server.ServerConnectionRegistry;
import tech.kwik.core.test.ByteUtils;
import tech.kwik.core.test.FieldReader;
import tech.kwik.core.test.FieldSetter;
import tech.kwik.core.test.TestClock;
import tech.kwik.core.test.TestScheduledExecutor;

import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;
import static tech.kwik.core.server.impl.ServerConnectorImpl.isValidLongHeaderPacket;


class ServerConnectorImplTest {

    private ServerConnectorImpl server;
    private DatagramSocket serverSocket;
    private Context context;
    private TestScheduledExecutor testExecutor;
    private TestClock clock;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        InputStream certificate = getClass().getResourceAsStream("localhost.pem");
        InputStream privateKey = getClass().getResourceAsStream("localhost.key");
        serverSocket = mock(DatagramSocket.class);
        server = new ServerConnectorImpl(serverSocket, certificate, privateKey, List.of(QuicConnection.QuicVersion.V1), false, new SysOutLogger());
        FieldSetter.setField(server, "acceptingNewConnections", true);
        server.registerApplicationProtocol("hq-interop", Mockito.mock(ApplicationProtocolConnectionFactory.class));
        clock = new TestClock();
        context = mock(Context.class);
        testExecutor = new TestScheduledExecutor(clock);
        when(context.getSharedServerExecutor()).thenReturn(testExecutor);
        when(context.getSharedScheduledExecutor()).thenReturn(testExecutor);
        FieldSetter.setField(server, "context", context);
    }

    @AfterEach
    void closeServerConnector() throws Exception {
        server.close(Duration.ofMillis(30));
    }

    //region versions
    @Test
    void unsupportedVersionLeadsToVersionNegotationPacket() throws Exception {
        // Given
        ByteBuffer buffer = ByteBuffer.allocate(1200);
        buffer.put((byte) 0b1100_0000);
        buffer.putInt(0xabababab);  // arbitrary reserved version
        buffer.put((byte) 8);
        buffer.put(new byte[8]);
        buffer.put((byte) 0);  // source connection id length

        // When
        server.process(createPacket(buffer));

        // Then
        verify(serverSocket).send(argThat(returnedPacket -> isVersionNegotiationPacket(returnedPacket.getData())));
    }

    @Test
    void packetWithUnsupportedVersionThatIsTooShortShouldBeDropped() throws Exception {
        // Given
        ByteBuffer buffer = ByteBuffer.allocate(1000);
        buffer.put((byte) 0b1100_0000);
        buffer.putInt(0xabababab);  // arbitrary reserved version
        buffer.put((byte) 8);
        buffer.put(new byte[8]);
        buffer.put((byte) 0);  // source connection id length

        // When
        server.process(createPacket(buffer));

        // Then
        verify(serverSocket, never()).send(any(DatagramPacket.class));
    }

    @Test
    void packetWithSupportedVersionThatIsTooShortShouldBeDropped() throws Exception {
        // Given
        ByteBuffer buffer = ByteBuffer.allocate(1000);
        buffer.put((byte) 0b1100_0000);
        buffer.putInt(Version.getDefault().getId());
        buffer.put((byte) 8);
        buffer.put(new byte[8]);
        buffer.put((byte) 0);  // source connection id length

        // When
        server.process(createPacket(buffer));

        // Then
        verify(serverSocket, never()).send(any(DatagramPacket.class));
    }

    @Test
    void unsupportedVersionWithLargeConnectionIdsShouldLeadToVersionNegotationPacket() throws Exception {
        // Given
        ByteBuffer buffer = ByteBuffer.allocate(1200);
        buffer.put((byte) 0b1100_0000);
        buffer.putInt(0xabababab);  // arbitrary reserved version
        buffer.put((byte) 28);
        buffer.put(new byte[28]);
        buffer.put((byte) 28);  // source connection id length

        // When
        server.process(createPacket(buffer));

        // Then
        verify(serverSocket).send(argThat(returnedPacket -> isVersionNegotiationPacket(returnedPacket.getData())));
    }

    @Test
    void versionNegotiationPacketShouldContainOriginalConnectionIds() throws Exception {
        // Given
        ByteBuffer buffer = ByteBuffer.allocate(1200);
        buffer.put((byte) 0b1100_0000);
        buffer.putInt(0xabababab);  // arbitrary reserved version
        buffer.put((byte) 8);
        buffer.put(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        buffer.put((byte) 4);  // source connection id length
        buffer.put(new byte[] { 11, 12, 13, 14 });

        // When
        server.process(createPacket(buffer));

        // Then
        verify(serverSocket).send(argThat(returnedPacket -> {
            VersionNegotiationPacket vn = new VersionNegotiationPacket();
            try {
                vn.parse(ByteBuffer.wrap(returnedPacket.getData()), null, 0, mock(Logger.class), 0);
                return Arrays.equals(vn.getDestinationConnectionId(), new byte[] { 11, 12, 13, 14 })
                        &&
                        Arrays.equals(vn.getSourceConnectionId(), new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
            }
            catch (Exception e) {
                return false;
            }
        }));
    }

    @Test
    void invalidInitialPacketShouldNotLeadToVersionNegotiationPacket() throws Exception {
        // Given
        ByteBuffer buffer = ByteBuffer.allocate(1200);
        buffer.put((byte) 0b1100_0000);
        buffer.putInt(Version.getDefault().getId());
        buffer.put((byte) 7);  // Invalid: initial destination connection id should be 8 bytes or longer
        buffer.put(new byte[] { 1, 2, 3, 4, 5, 6, 7 });
        buffer.put((byte) 4);  // source connection id length
        buffer.put(new byte[] { 11, 12, 13, 14 });

        // When
        server.process(createPacket(buffer));

        // Then
        verify(serverSocket, never()).send(any(DatagramPacket.class));
    }
    //endregion

    //region initial packets
    @Test
    void serverReceivingValidInitialShouldCreateNewConnection() throws Exception {
        // Given
        ServerConnectionImpl connection = createMockServerConnection();
        ServerConnectionFactory connectionFactory = installServerConnectionFactoryReturning(connection);

        // When
        server.process(createPacket(ByteBuffer.wrap(ByteUtils.hexToBytes(validInitialAsHex()))));
        testExecutor.check();

        // Then
        verify(connectionFactory).createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class), any(byte[].class), any());
        verify(connection).processPacket(any(QuicPacket.class), any(PacketMetaData.class));
    }

    @Test
    void receivingDuplicateInitialShouldNotCreateNewConnection() throws Exception {
        // Given
        byte[] orginalDcid = ByteUtils.hexToBytes("f8e39b14d954c988");
        ServerConnectionImpl connection = mock(ServerConnectionImpl.class);
        when(connection.getSourceConnectionId()).thenReturn(ByteUtils.hexToBytes("cafebabe"));
        when(connection.getInitialConnectionId()).thenReturn(ByteUtils.hexToBytes("cafebabe"));
        when(connection.getOriginalDestinationConnectionId()).thenReturn(orginalDcid);

        var connectionFactory = installServerConnectionFactoryReturning(connection);

        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(validInitialAsHex()));

        server.process(createPacket(buffer));
        testExecutor.check();

        verify(connectionFactory).createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class), any(byte[].class), any());
        clearInvocations(connectionFactory);

        // When
        server.process(createPacket(buffer));
        verify(connectionFactory, never()).createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class), any(byte[].class), any());
    }

    @Test
    void truncatedLongHeaderPacketShouldBeIgnoredWithoutException() {
        // Given
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("c0 00000001 08 0102030405060708".replace(" ", "")));

        // When
        server.process(createPacket(buffer));
    }

    @Test
    void longHeaderPacketWithInvalidSourceConnectionIdLengthShouldBeIgnoredWithoutException() {
        // Given
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("c0 00000001 08 0102030405060708 ff".replace(" ", "")));

        // When
        server.process(createPacket(buffer));
    }

    @Test
    void duplicatedButCorruptedFirstPacketShouldNotChangeServerState() throws Exception {
        RawPacket validFirstPacket = createPacket(ByteBuffer.wrap(ByteUtils.hexToBytes("c900000001088f609080b6d8a632000044d2a83ef8d31f6996534343e3e85cb20cef2df1bad56ee0b89738899b4c152dd706c780ffe6ff2612524c58d32d99c357b9afbbf435e4953b7257d11d676cc472ce9a8be664c11bc37679c68c6063f387f9de8775b7dfe9e48fab013c4919b443339b0d99ac79dac58f053b8b8080f6984b8190dcd5e7bdc0c70beefb392659cbf3fc26b2b9f85174de87766b97eb1a83d1d0ce14b7b211da106a8bf563e4cacc365a79717a4d7213b2f20392d648a8bd8ec42f80c4463b36338c39df6ad5506902651e2105caec47e90396281fa6ce2222d3d09a4db68fb5864cb7c27f8b6e85e046ffa24bd2eecb7fe2d6a4c75ed9666dfd00e32c702987f7fe1eb785c8394ab5cdabeb25ec829d44caab9c61c8d8143f3ba91308fc90a60b61430be992df056f1371749b1cd5c8da640b9637dda85bb2cf172c0642a0d6c33a31f2178dc7cca4d1a50efbba83bb7a6db13432c822f3700ed94e849ceb11342e0081f1fef2705780385cdec8e798be754965abc3f9ccde35670f43391b3601cfc68c78c89d74fdcf394e74e5a3c3eadb952a541a955a78f0211f2136b16cb0919541e74c50d50be561baae4ab3ab555bd5ec62bc2d59fed7a8cbf89f000bb1a7a8a81b2a5fb2ca65e42838b3fadc2e8c6d96be79a290bf3a92f5eab953982986c5f2b0396684f07c7ebac9658caa454d749716e4bea55973b50b83faaf4bbac13bf3be1e473471e2f9e07b28db2bf5763ce342cfb952954424fc3d4e3b935cfaf322dc53d73376361f4662baac2f20b1e168ba2c0711536983b8bd15322cf28c2524d1e08510528c8f09d25525b387e26462104743aecf667571db14c1e73fa52c23f54e36b1c1cc2224f501943688d301d29b897e05d63f1b4a3e5fafee04096cc8e4f49b3f9358c86daaa3d10c54caa9a81676b5c74bb9ebd933adc4fae88acd5ace9ca33f22bb06fab30083328951cfeeb68cb5227e458bbbd65a5f8e1363afe2ef4a065102f732409685efa3525684ab2a513a8f4eabce1c698898ed0c4e6064f9c322d0467ef150f5fedd41258110f0742a436c4bbd1a6899141b2a06deec018ff366ff334f4dbff93c756d8c9db0997d97f7bf1b160ea678d316642fd5842027259503be9dd759b6fa898191bb79ccc84bd294c4f62a5f892a088247757cadb0113b22c444dd6e115dd6fbc1e537dd7ff83789a2fb31b5852546386e01fb06e9130845f9bb38986c7aab6bde6ca04607a98aa89cd2921ebb3ecca4470b5b7def2e376ab028454f4a8fc88c2041315cf399a1c53d5ecdb7b7797a69a06ddced1ba2e32984de47d9f85724121a51d1a0b37d6ebfac2b7ace538be777668bc3692beb125a4eed5e59929df22c1f5735e5fd7fd4b9e08112a94a124000bdf4f57ebd040e615bbb481340d4e8c707280d7ea77ce67044821b1d6c8e97ccad2d5cc704207393ec8a62bc2b4257e4c6d66d9a72d686eea4c49c13c5c64d2e0077affc09727bb16339e2f335e3a1bfd0824abf7a073b2f5f1123aa8cca0b9d926334bc8f6710348e1fd002a8176b20c6be10e968ff14078a6d0c7cddede062b055b9344668feab526dc3972d9da20a81dcf8207f60eb83f3d0083d35d0ff5d735e89d4abc5044307046d4b58a9ba6eb5ff07dbbd8146cc532ea18ed82a6e5b193dea2d8a5b85c529be1a954ce3d35e912066af60674f773d5d9543bef0ffba5e317379955b05629f980c9ac22cb61a037324ec730227ae25ab9a")));
        RawPacket invalidRepeatedFirstPacket = createPacket(ByteBuffer.wrap(ByteUtils.hexToBytes("cb00000001088f609080b6d8a632000044d2d98d211be37aef9c9cc71cf2a89a9fa9ccfd2cd390c7ec84d6d34d4205e033738c0bf51fbda6f2a502b421d02a8116233e006a8dddab9fb691e9ef99ae7553aa0ee67b18db0ac0dd0262f02bbdc4485519a2be071e3f763ebbff3e702efc1a6249a23556c2d03ae6dc0fe3190c823d6e50ca06a44e809f898394ba64a251c980c160f6acce407cfa0254e28da288dc4e883225239e49a546de2fe91e3d4c369e2ffd01a869805f1bfb518b9a82b5f48e75c2ccc6747d14d203955348788de5bdeb239e362c5cdaeb34ac31dbf5766e4facba76f8ef14062b0bc153a7143ba0f4e0f5df03714f1f1afe3453a24eea1cf14c9245300ee8cb2c8c2fc4a8f3a052d8af61dfc7aa09b335bff6a7a11484fc74e397fa4ddb3552a7420d0f44b36636c309ee763915c5e5df0ea322beabfb8eab9f98154ed36a9368c8fcf7c36ff4ac47c3fca8d5a59f951b4f52c5c4c053df37abfc0900ecc2f0b00bde167a3af9d55f7e6518e7347c09f238e106978423c30f8a7dbf4f9223d482cc7a995f2cb4658a0f8468e13aeb624d0ab91a3a23d6853894e42a8c2a9e2782a924b28a372778605d0d5bca7cab6ba50dc13162a96d052f34e4299558d70c13526f7dd6f9e962ff60b418bde4c6383ef668a80ac82db1f32976c46e8de40362e8565feab5f9a277a7c67a41ecd6d51ac7df90c740676e19f1679844ef78600eb772497e93eaecada58f156d5e15cda00218dfb7099f4c69c980a3af6e2530e0dca5de935495167641bc25d73bb2a500f64175f2963e0c3a2cc5ada7af944047a140d337b92bcd541d02a7f0d2a4554c786a492c57b73cb5a3654c616e096628c80a19596e45097579fad52cb28e9ae2cc678fd026ea1dc4ceb655c0a65bd6a0083a76ac83e1ff5b6462db9ed32c6488d8402c8b1513fb4391a4bd36d2e37e1e5f0661f61627eed605cc19b9574f75b0e43c879a68ed84985db3f2e8a3f738608acebeb260bcccdd7afd0a6fe805f6ca6eed0d0c9f1fbcbe427e7117a2d6ab75988abab33c83bbf1f67dbba97e09f0fc76ab15cfb04b4a3b3309079bd8e380fa5cfbb36829f70f1474c71e6b7c33cb8eec6a792068bebabf505640f67fa150444d1aa9f567dd4364dc49bf7a54379481d3a9937878db0a2bce55436b69d82bc389bbd79e5f1071a46a3d4c718092bb29bd2364f38db0f8d8a20a56f781b30f3379c1723dea084ce25bf6490f6be0fab8ee97fdca22c22aeb266468b90cae87aea2bf226091fecfc04c5cd0da55b0b14dbbbb3d26be7b47a0e9a35ae47724c5a0949fef6dd5ec5fe608420caa769ea4126a18b0a5649ca614de40187dce3a2b1b91b011b04104b6c0c3f73abb21eea3f3ba60867fd30d56d7596fa40315f8a55567f7b7ccbffac66b0349eccc3e175412b4ceb2fda45c16114841ab2eaad9cdcda93dda458c8a87466a1a5128b826bdedc941e1a4721146fa2e5ac1e93bea37c94ebd64d04a3828740f34db80dfce8d704e866e3970a31f07042de0b27fe8da3344717c9453554101efa238fb36072c0fc35b018ea9241a4660a3fa9d386813f2e1cc6bb48b1bc759523378f06ce0bba12a168899eb8988d1d26282506ac8077889e192ae80738945e91f03200d9e3bcf933a28c83a698b2a4a712f305e639b2de139416d6fb38da9b6db60631c7a4358ab405f9d2ea240424422329918a94c7cbec44e6268cd32de1e5924d204333c68c3a379827af5f3a53b33")));

        server.process(validFirstPacket);
        server.process(invalidRepeatedFirstPacket);
        testExecutor.check();

        ServerConnectionRegistryImpl connectionRegistry = (ServerConnectionRegistryImpl) new FieldReader(server, server.getClass().getDeclaredField("connectionRegistry")).read();
        // As the first packet was valid, there must be an entry with the original DCID
        assertThat(connectionRegistry.isExistingConnection(null, ByteUtils.hexToBytes("8f609080b6d8a632"))).isPresent();
    }

    @Test
    void whenServerIsNotAcceptingNewConnectionsAnyInitialShouldLeadToConnectionRefused() throws Exception {
        server.stopAcceptingNewConnections();
        ByteBuffer packetBytes = ByteBuffer.wrap(ByteUtils.hexToBytes(validInitialAsHex()));
        packetBytes.position(5);
        byte[] dcid = new byte[packetBytes.get()];
        packetBytes.get(dcid);
        packetBytes.position(0);

        // When
        server.process(createPacket(packetBytes));

        // Then
        verify(serverSocket).send(argThat(data -> isInitialWithConnectionCloseFrameWithError(data.getData(), dcid, QuicConstants.TransportErrorCode.CONNECTION_REFUSED.value)));
    }
    //endregion

    //region close connection
    @Test
    void closingConnectionsShouldCloseConnections() throws Exception {
        // Given
        ServerConnectionImpl connection = createMockServerConnection();
        installServerConnectionFactoryReturning(connection);

        server.process(createPacket(ByteBuffer.wrap(ByteUtils.hexToBytes(validInitialAsHex()))));
        testExecutor.check();

        // When
        server.closeAllConnections();

        // Then
        verify(connection, atLeastOnce()).close();
    }
    //endregion

    //region handshake packet
    @Test
    void receivingHandshakePacketShouldNotLeadToAnyFormOfConnection() throws Exception {
        // Given
        ServerConnectionImpl connection = createMockServerConnection();
        installServerConnectionFactoryReturning(connection);

        // When
        server.process(createPacket(ByteBuffer.wrap(ByteUtils.hexToBytes(plausibleHandshakeAsHex()))));
        testExecutor.check();

        // Then
        ServerConnectionRegistry connectionRegistry = (ServerConnectionRegistry) new FieldReader(server, server.getClass().getDeclaredField("connectionRegistry")).read();
        assertThat(connectionRegistry.getAllConnections()).isEmpty();
    }
    //endregion

    //region RFC-8889
    @Test
    void testIsValidLongHeaderPacketAccordingToRFC8889() {
        assertThat(isValidLongHeaderPacket(toByteBuffer("c0 00000001 08 0102030405060708 0c 0102030405060708090a0b0c cafe babe"))).isTrue();
        assertThat(isValidLongHeaderPacket(toByteBuffer("c0 00000001 08 0102030405060708 08 010203"))).isFalse();
        assertThat(isValidLongHeaderPacket(toByteBuffer("c0 00000001 08 0102030405060708 08"))).isFalse();
        assertThat(isValidLongHeaderPacket(toByteBuffer("c0 00000001 08 0102030405060708"))).isFalse();
        assertThat(isValidLongHeaderPacket(toByteBuffer("c0 00000001 08 01020304050607"))).isFalse();
        assertThat(isValidLongHeaderPacket(toByteBuffer("c0 00000001 00 00"))).isFalse();
        assertThat(isValidLongHeaderPacket(toByteBuffer("40 00000001 08 0102030405060708 0c 0102030405060708090a0b0c cafe babe"))).isFalse();
    }
    //endregion

    //region close server connector
    @Disabled  // flaky
    @Test
    void afterCloseNoAdditionalThreadsShouldBePresent() throws Exception {
        // Given
        List<String> threadsBefore = getActiveThreadNames();
        // Initialize server object (another one) after threadsBefore is determined
        initObjectUnderTest();

        // When
        server.start();
        Thread.sleep(10);

        List<String> threadsDuring = getActiveThreadNames();

        server.close();
        Thread.sleep(10);

        // Then
        List<String> threadsAfter = getActiveThreadNames();
        assertThat(threadsAfter).containsExactlyInAnyOrderElementsOf(threadsBefore);
        assertThat(threadsDuring.size()).isGreaterThan(threadsBefore.size());  // Just to be sure that threads are started
    }

    @Test
    void afterCloseSocketShouldBeClosed() throws InterruptedException {
        // When
        server.start();
        Thread.sleep(10);
        server.close();

        // Then
        verify(serverSocket).close();
    }
    //endregion

    //region helper methods
    private ByteBuffer toByteBuffer(String hexData) {
        return ByteBuffer.wrap(ByteUtils.hexToBytes(hexData.replace(" ", "")));
    }

    private String plausibleHandshakeAsHex() {
        return "e000000001088f609080b6d8a632000044d2a83ef8d31f6996534343e3e85cb20cef2df1ba";
    }

    private ServerConnectionImpl createMockServerConnection() {
        ServerConnectionImpl connection = mock(ServerConnectionImpl.class);
        when(connection.getSourceConnectionId()).thenReturn(new byte[8]);
        when(connection.getInitialConnectionId()).thenReturn(new byte[8]);
        when(connection.getOriginalDestinationConnectionId()).thenReturn(new byte[8]);
        return connection;
    }

    private ServerConnectionFactory installServerConnectionFactoryReturning(ServerConnectionImpl connection) throws Exception {
        ServerConnectionFactory connectionFactory = mock(ServerConnectionFactory.class);
        when(connectionFactory.createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class), any(byte[].class), any()))
                .thenReturn(connection);
        when(connectionFactory.createServerConnectionProxy(any(ServerConnectionImpl.class), any(List.class), any(ByteBuffer.class), any(PacketMetaData.class)))
                .thenAnswer(i -> new ServerConnectionThreadDummy(i.getArgument(0), (InitialPacket) ((List) i.getArgument(1)).get(0), ((PacketMetaData) i.getArgument(3))));

        FieldSetter.setField(server, server.getClass().getDeclaredField("serverConnectionFactory"), connectionFactory);
        return connectionFactory;
    }

    private RawPacket createPacket(ByteBuffer buffer) {
        DatagramPacket datagram = new DatagramPacket(buffer.array(), 0, buffer.limit(), new InetSocketAddress(InetAddress.getLoopbackAddress(), 38675));
        RawPacket packet = new RawPacket(datagram, Instant.now(), 0);
        return packet;
    }

    private boolean isVersionNegotiationPacket(byte[] data) {
        try {
            VersionNegotiationPacket vn = new VersionNegotiationPacket();
            vn.parse(ByteBuffer.wrap(data), null, 0, mock(Logger.class), 0);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isInitialWithConnectionCloseFrameWithError(byte[] packetBytes, byte[] dcid, int expectedError) {
        try {
            InitialPacket initialPacket = new InitialPacket(Version.getDefault());
            ConnectionSecrets secrets = new ConnectionSecrets(VersionHolder.with(Version.getDefault()), Role.Client, null, mock(Logger.class));
            secrets.computeInitialKeys(dcid);
            initialPacket.parse(ByteBuffer.wrap(packetBytes), secrets.getPeerAead(EncryptionLevel.Initial), 0, mock(Logger.class), 0);
            return initialPacket.getFrames().stream()
                    .anyMatch(frame -> frame instanceof ConnectionCloseFrame && ((ConnectionCloseFrame) frame).getErrorCode() == expectedError);
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String validInitialAsHex() {
        // DCID == e03c1fe06e9141cfb854f6cb6249cdd5d4e2
        return "cc0000000112e03c1fe06e9141cfb854f6cb6249cdd5d4e21162f4a4a4d65784c78cd085828889385cb90044b79ff2be3251fc6b901291f50364c54e5b9da023e0ca517ac040db0f6539d3d24bd78d16b867b2f6002abd58ec30dd6c62527aa13f6c931b30be5d594469733b443311ba6fbc560fdde38b6968dbbdacc79b5b4f9b710e5aca0a670479fe29d1376becfb28740578a9ee4b7e82135042893f8f7872f377605b785ffca292f5a99074bdf0d95eacb25f4e897726ab495e72eff8b0cebf8c4fe0cbb2d303cfc97a716595b437a054820c032052fd7b17275e49684ce3b6572623a22f64087c33c65e306b5cadf3e268bc2ba19fa53aa836000f2f9cec92bf0c629fde7a00efc878f61e80efb1f1523aabb7ae430574ed484d284b3ad7a7e8c51ad18b53e3a50e2f5e95748e77c7a1c87aad27e1338ad07c5218695d5b877f4a5e05a52b1169038f80a41be4019668f8b3d735bb00bd9ce55c7e5f57743d5794bb9ed64462f8c31fece2b362ef7a22c8f0b3482378f8dbc0be8c078408b47bdfbeeb8dad7d1d14a348a71a7801faaf752d2ae55b66025ef71a12bcdb6ce61587251cce2fd62f4ede36cc8afeb34720d0abc06086a22cd30460098b7ba43f4a99b3b45a0720d37d3319cadd48055a30cbced0e1810e15ff4c27d1274423033e2f07b375ca1a02b2bb7f7baa7642052b62d8b435ac8ef1f1259257d0835db797c80f6eac7b11ce3b2bcb0a15673c74fac36a93b572b71e0abc1e95f0c911a68636738e4463472cabccc252978f46b914584e27e4ff438e42ecb41fbf06c733fe75ae0caf0203bf9141d1915da1e5491a07c59d4cff284370ddc68f29788f2f21f63d03fee614969d7c9ec8de0a4d30edc53ca027367e8b441569ea5b2e106d63ff7717739c2981af1e886c8411385da96383f00b780d0446b43835e0f856911d83081eeccc44dedc3ce2e043071892e485c68a01b4a02606b9238da7d6667c1960d28cb49ca0fe264ced99a90450ddbea009619d610960d7aada2c62f90fcc71d7bac6e6ae8cda184e6c0996de7efed7991f388350caa0ff6b0e5c06fa7b65dd9c7cef2af1e6b25b5f21c9a390fd09fbe1803f32546cca14961bc6f8bc6c9306d96eb3066fef7d7836b9dcc0c15175b04e207839bc0d9a2f3204629ab7ec5125d07920906fcdeea160db8b80ff55e4faffd09fbaa71820c8dd8a835730a5781bdfcb6cd9421a325db900c7d18d87c375495c0ee99efeebd4ad41c9c95176ca1965da2d355272f1b65bfc7004a46307198e261c9c0bc4151f8963a43d300017b5b01eb9265aa82bc753c9088635d120daa10d3458a0380559eea968577debc18f89df22eafa2b13d5b313bc74f8e23653241c8cd42eb73d5aa4be92adbd3ba541f4b80ed98a9a96bf6bb08ef145987927ff2dd491554ced7efb6ef1931fa00c7b16eb1a6519fc3518c0e9e09e8d0756145acfa058828e1ade21ad6067c03b8b236a0a876016b57f0beae846d47c649bfc70b7b38ab79730728e24785765b2c16755ed24391f8abc47acb7005f05256ab635cb86ae24226cea9e41837172de66ee0e327455a1ce404c2e04fbe04eb281310bc6a01586ea49de8bd86453f2d6a2b35c7012f16aab2c5f8d716d5bca22674cec644dddb291f07f6f3e19570c60d660cf8912833c46a27403b93ae4cbff6f5891a1103a5477782d311b6bcd0eff99fec82d03d40507ce11289757487a8a9ecda199d594c6253b8f1563c5c20586f70895";
    }

    private static List<String> getActiveThreadNames() {
        ThreadGroup mainGroup = Thread.currentThread().getThreadGroup();
        Thread[] threads = new Thread[2 * mainGroup.activeCount()];
        int count = mainGroup.enumerate(threads);
        return Arrays.stream(threads)
                .limit(count)
                .map(Thread::getName)
                .collect(Collectors.toList());
    }
    //endregion
}