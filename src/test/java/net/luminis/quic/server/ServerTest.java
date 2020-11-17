package net.luminis.quic.server;

import net.luminis.quic.*;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.crypto.Keys;
import net.luminis.quic.frame.CryptoFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.VersionNegotiationPacket;
import net.luminis.tls.handshake.ClientHello;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.internal.util.reflection.FieldSetter;

import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

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
        when(connectionFactory.createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class)))
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
        verify(connectionFactory).createNewConnection(any(Version.class), any(InetSocketAddress.class), any(byte[].class));
        // And
        verify(connection).parsePackets(anyInt(), any(Instant.class), argThat(data -> data.limit() == 1200));
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