package net.luminis.quic.server;

import net.luminis.quic.*;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.frame.CryptoFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.packet.VersionNegotiationPacket;
import net.luminis.quic.tls.QuicTransportParametersExtension;
import net.luminis.tls.KeyUtils;
import net.luminis.tls.extension.ApplicationLayerProtocolNegotiationExtension;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.handshake.ClientHello;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.internal.util.reflection.FieldSetter;

import java.io.File;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

class ServerTest {

    private Server server;
    private DatagramSocket serverSocket;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        InputStream certificate = getClass().getResourceAsStream("localhost.pem");
        InputStream privateKey = getClass().getResourceAsStream("localhost.key");
        serverSocket = mock(DatagramSocket.class);
        server = new Server(serverSocket, certificate, privateKey, List.of(Version.getDefault(), Version.QUIC_version_1), false, new File("."));
    }

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
                return Arrays.equals(vn.getDcid(), new byte[] { 11, 12, 13, 14 })
                        &&
                        Arrays.equals(vn.getScid(), new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
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

    @Test
    void serverReceivingValidInitialShouldCreateNewConnection() throws Exception {
        // Given
        ServerConnectionFactory connectionFactory = mock(ServerConnectionFactory.class);
        ServerConnectionImpl connection = mock(ServerConnectionImpl.class);
        when(connection.getSourceConnectionId()).thenReturn(new byte[8]);
        when(connection.getOriginalDestinationConnectionId()).thenReturn(new byte[8]);
        when(connectionFactory.createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class), any(byte[].class)))
                .thenReturn(connection);
        FieldSetter.setField(server, server.getClass().getDeclaredField("serverConnectionFactory"), connectionFactory);

        // When
        server.process(createPacket(ByteBuffer.wrap(ByteUtils.hexToBytes(validInitialAsHex()))));
        Thread.sleep(300);

        // Then
        verify(connectionFactory).createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class), any(byte[].class));
        // And
        verify(connection).parseAndProcessPackets(anyInt(), any(Instant.class), any(ByteBuffer.class), argThat(packet -> packet instanceof InitialPacket));
    }

    @Test
    void newServerConnectionUsesOriginalScidAsDcid() throws Exception {
        // TODO: this test is more an integration test. Testing correct use of connection id's can be tested on serverconnection directly
        byte[] scid = new byte[] { 1, 2, 3, 4, 5 };
        TransportParameters clientTransportParams = new TransportParameters();
        clientTransportParams.setInitialSourceConnectionId(scid);
        List<Extension> clientExtensions = List.of(new ApplicationLayerProtocolNegotiationExtension("hq-29"),
                new QuicTransportParametersExtension(Version.getDefault(), clientTransportParams, Role.Client));

        ClientHello ch = new ClientHello("localhost", KeyUtils.generatePublicKey(), false, clientExtensions);
        CryptoFrame cryptoFrame = new CryptoFrame(Version.getDefault(), ch.getBytes());
        byte[] dcid = new byte[] { 11, 12, 13, 14, 15, 16, 17, 18 };
        InitialPacket initialPacket = new InitialPacket(Version.getDefault(), scid, dcid, null, cryptoFrame);
        ConnectionSecrets connectionSecrets = new ConnectionSecrets(Version.getDefault(), Role.Client, null, mock(Logger.class));
        connectionSecrets.computeInitialKeys(dcid);
        byte[] packetBytes = initialPacket.generatePacketBytes(0L, connectionSecrets.getOwnSecrets(EncryptionLevel.Initial));
        server.process(createPacket(ByteBuffer.wrap(packetBytes)));
        Thread.sleep(100);  // Because processing packets is done on seperate thread.

        // Then
        ArgumentCaptor<DatagramPacket> captor = ArgumentCaptor.forClass(DatagramPacket.class);
        verify(serverSocket, atLeast(1)).send(captor.capture());
        DatagramPacket packetSent = captor.getValue();
        int dcidLength = packetSent.getData()[5];
        byte[] responseDcid = Arrays.copyOfRange(packetSent.getData(), 6, 6 + dcidLength);

        assertThat(responseDcid).isEqualTo(scid);

        int scidLength = packetSent.getData()[6 + dcidLength];
        byte[] responseScid = Arrays.copyOfRange(packetSent.getData(), 6 + dcidLength + 1, 6 + dcidLength + 1 + scidLength);
        assertThat(responseScid).isNotEqualTo(dcid);
    }

    @Test
    void receivingDuplicateInitialShouldNotCreateNewConnection() throws Exception {
        // Given
        byte[] orginalDcid = ByteUtils.hexToBytes("f8e39b14d954c988");
        ServerConnectionImpl connection = mock(ServerConnectionImpl.class);
        when(connection.getSourceConnectionId()).thenReturn(ByteUtils.hexToBytes("cafebabe"));
        when(connection.getOriginalDestinationConnectionId()).thenReturn(orginalDcid);

        ServerConnectionFactory connectionFactory = mock(ServerConnectionFactory.class);
        when(connectionFactory.createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class), any(byte[].class)))
                .thenReturn(connection);
        FieldSetter.setField(server, server.getClass().getDeclaredField("serverConnectionFactory"), connectionFactory);

        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(validInitialAsHex()));

        server.process(createPacket(buffer));
        Thread.sleep(100);

        verify(connectionFactory).createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class), any(byte[].class));
        clearInvocations(connectionFactory);

        // When
        server.process(createPacket(buffer));
        verify(connectionFactory, never()).createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class), any(byte[].class));
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

    private String validInitialAsHex() {
        return "cc0000000112e03c1fe06e9141cfb854f6cb6249cdd5d4e21162f4a4a4d65784c78cd085828889385cb90044b79ff2be3251fc6b901291f50364c54e5b9da023e0ca517ac040db0f6539d3d24bd78d16b867b2f6002abd58ec30dd6c62527aa13f6c931b30be5d594469733b443311ba6fbc560fdde38b6968dbbdacc79b5b4f9b710e5aca0a670479fe29d1376becfb28740578a9ee4b7e82135042893f8f7872f377605b785ffca292f5a99074bdf0d95eacb25f4e897726ab495e72eff8b0cebf8c4fe0cbb2d303cfc97a716595b437a054820c032052fd7b17275e49684ce3b6572623a22f64087c33c65e306b5cadf3e268bc2ba19fa53aa836000f2f9cec92bf0c629fde7a00efc878f61e80efb1f1523aabb7ae430574ed484d284b3ad7a7e8c51ad18b53e3a50e2f5e95748e77c7a1c87aad27e1338ad07c5218695d5b877f4a5e05a52b1169038f80a41be4019668f8b3d735bb00bd9ce55c7e5f57743d5794bb9ed64462f8c31fece2b362ef7a22c8f0b3482378f8dbc0be8c078408b47bdfbeeb8dad7d1d14a348a71a7801faaf752d2ae55b66025ef71a12bcdb6ce61587251cce2fd62f4ede36cc8afeb34720d0abc06086a22cd30460098b7ba43f4a99b3b45a0720d37d3319cadd48055a30cbced0e1810e15ff4c27d1274423033e2f07b375ca1a02b2bb7f7baa7642052b62d8b435ac8ef1f1259257d0835db797c80f6eac7b11ce3b2bcb0a15673c74fac36a93b572b71e0abc1e95f0c911a68636738e4463472cabccc252978f46b914584e27e4ff438e42ecb41fbf06c733fe75ae0caf0203bf9141d1915da1e5491a07c59d4cff284370ddc68f29788f2f21f63d03fee614969d7c9ec8de0a4d30edc53ca027367e8b441569ea5b2e106d63ff7717739c2981af1e886c8411385da96383f00b780d0446b43835e0f856911d83081eeccc44dedc3ce2e043071892e485c68a01b4a02606b9238da7d6667c1960d28cb49ca0fe264ced99a90450ddbea009619d610960d7aada2c62f90fcc71d7bac6e6ae8cda184e6c0996de7efed7991f388350caa0ff6b0e5c06fa7b65dd9c7cef2af1e6b25b5f21c9a390fd09fbe1803f32546cca14961bc6f8bc6c9306d96eb3066fef7d7836b9dcc0c15175b04e207839bc0d9a2f3204629ab7ec5125d07920906fcdeea160db8b80ff55e4faffd09fbaa71820c8dd8a835730a5781bdfcb6cd9421a325db900c7d18d87c375495c0ee99efeebd4ad41c9c95176ca1965da2d355272f1b65bfc7004a46307198e261c9c0bc4151f8963a43d300017b5b01eb9265aa82bc753c9088635d120daa10d3458a0380559eea968577debc18f89df22eafa2b13d5b313bc74f8e23653241c8cd42eb73d5aa4be92adbd3ba541f4b80ed98a9a96bf6bb08ef145987927ff2dd491554ced7efb6ef1931fa00c7b16eb1a6519fc3518c0e9e09e8d0756145acfa058828e1ade21ad6067c03b8b236a0a876016b57f0beae846d47c649bfc70b7b38ab79730728e24785765b2c16755ed24391f8abc47acb7005f05256ab635cb86ae24226cea9e41837172de66ee0e327455a1ce404c2e04fbe04eb281310bc6a01586ea49de8bd86453f2d6a2b35c7012f16aab2c5f8d716d5bca22674cec644dddb291f07f6f3e19570c60d660cf8912833c46a27403b93ae4cbff6f5891a1103a5477782d311b6bcd0eff99fec82d03d40507ce11289757487a8a9ecda199d594c6253b8f1563c5c20586f70895";
    }
}