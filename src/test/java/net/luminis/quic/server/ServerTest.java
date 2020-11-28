package net.luminis.quic.server;

import net.luminis.quic.*;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.frame.CryptoFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.VersionNegotiationPacket;
import net.luminis.quic.tls.QuicTransportParametersExtension;
import net.luminis.tls.KeyUtils;
import net.luminis.tls.extension.ApplicationLayerProtocolNegotiationExtension;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.handshake.ClientHello;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.internal.util.reflection.FieldSetter;

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
        server = new Server(serverSocket, certificate, privateKey, List.of(Version.getDefault()));
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
    void serverReceivingValidInitialShouldCreateNewConnection() throws Exception {
        // Given
        ServerConnectionFactory connectionFactory = mock(ServerConnectionFactory.class);
        ServerConnection connection = mock(ServerConnection.class);
        when(connection.getSourceConnectionId()).thenReturn(new byte[8]);
        when(connectionFactory.createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class), any(byte[].class)))
                .thenReturn(connection); // new ServerConnection(Version.getDefault(), serverSocket, null, new byte[8], null, 100, mock(Logger.class)));
        FieldSetter.setField(server, server.getClass().getDeclaredField("serverConnectionFactory"), connectionFactory);

        ByteBuffer buffer = ByteBuffer.allocate(1200);
        buffer.put((byte) 0b1100_0000);
        buffer.putInt(Version.getDefault().getId());
        buffer.put((byte) 8);
        buffer.put(new byte[8]);
        buffer.put((byte) 0);  // source connection id length

        // When
        server.process(createPacket(buffer));

        // Then
        verify(connectionFactory).createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class), any(byte[].class));
        // And
        verify(connection).parsePackets(anyInt(), any(Instant.class), argThat(data -> data.limit() == 1200));
    }

    @Test
    void newServerConnectionUsesOriginalScidAsDcid() throws Exception {
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
        byte[] packetBytes = initialPacket.generatePacketBytes(0, connectionSecrets.getOwnSecrets(EncryptionLevel.Initial));
        server.process(createPacket(ByteBuffer.wrap(packetBytes)));

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
        ServerConnection connection = mock(ServerConnection.class);
        when(connection.getSourceConnectionId()).thenReturn(ByteUtils.hexToBytes("cafebabe"));
        when(connection.getOriginalDestinationConnectionId()).thenReturn(orginalDcid);

        ServerConnectionFactory connectionFactory = mock(ServerConnectionFactory.class);
        when(connectionFactory.createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class), any(byte[].class)))
                .thenReturn(connection);
        FieldSetter.setField(server, server.getClass().getDeclaredField("serverConnectionFactory"), connectionFactory);

        ByteBuffer buffer = ByteBuffer.allocate(1200);
        buffer.put((byte) 0b1100_0000);
        buffer.putInt(Version.getDefault().getId());
        buffer.put((byte) orginalDcid.length);
        buffer.put(orginalDcid);
        buffer.put((byte) 0);  // source connection id length

        server.process(createPacket(buffer));
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

}