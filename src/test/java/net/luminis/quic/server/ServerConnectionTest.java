package net.luminis.quic.server;

import jdk.jshell.spi.ExecutionControlProvider;
import net.luminis.quic.*;
import net.luminis.quic.Version;
import net.luminis.quic.frame.FrameProcessor3;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.tls.QuicTransportParametersExtension;
import net.luminis.quic.frame.ConnectionCloseFrame;
import net.luminis.quic.frame.CryptoFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.send.SenderImpl;
import net.luminis.tls.*;
import net.luminis.tls.alert.HandshakeFailureAlert;
import net.luminis.tls.extension.ApplicationLayerProtocolNegotiationExtension;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.handshake.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.internal.util.reflection.FieldReader;
import org.mockito.internal.util.reflection.FieldSetter;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.awt.image.ImageProducer;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;


class ServerConnectionTest {

    public static final String DEFAULT_APPLICATION_PROTOCOL = "hq-29";
    private ServerConnection connection;
    private ApplicationLayerProtocolNegotiationExtension alpn = new ApplicationLayerProtocolNegotiationExtension(DEFAULT_APPLICATION_PROTOCOL);
    private TlsServerEngine tlsServerEngine;

    @BeforeEach
    void setupObjectUnderTest() throws Exception {
        TlsServerEngineFactory tlsServerEngineFactory = createTlsServerEngine();
        connection = createServerConnection(tlsServerEngineFactory);
    }

    @Test
    void whenParsingClientHelloLeadsToTlsErrorConnectionIsClosed() throws Exception {
        // When
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, new CryptoFrame(Version.getDefault(), new byte[123])), Instant.now());

        // Then
        verify(connection.getSender()).send(argThat(frame -> frame instanceof ConnectionCloseFrame), eq(EncryptionLevel.Initial));
    }

    @Test
    void engineNotBeingAbleToNegotiateCipherShouldCloseConnection() throws Exception {
        // Given
        ((MockTlsServerEngine) tlsServerEngine).injectErrorInReceivingClientHello(() -> new HandshakeFailureAlert(""));

        // When
        List<Extension> clientExtensions = List.of(alpn, createTransportParametersExtension());
        ClientHello ch = new ClientHello("localhost", KeyUtils.generatePublicKey(), false,
                List.of(TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256), List.of(TlsConstants.SignatureScheme.rsa_pss_pss_sha256), TlsConstants.NamedGroup.secp256r1, clientExtensions);
        CryptoFrame cryptoFrame = new CryptoFrame(Version.getDefault(), ch.getBytes());
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, cryptoFrame), Instant.now());

        // Then
        verify(connection.getSender()).send(argThat(frame -> frame instanceof ConnectionCloseFrame), eq(EncryptionLevel.Initial));
    }

    @Test
    void failingAlpnNegotiationLeadsToCloseConnection() throws Exception {
        // When
        List<Extension> clientExtensions = List.of(new ApplicationLayerProtocolNegotiationExtension("h2"), createTransportParametersExtension());
        ClientHello ch = new ClientHello("localhost", KeyUtils.generatePublicKey(), false, clientExtensions);
        CryptoFrame cryptoFrame = new CryptoFrame(Version.getDefault(), ch.getBytes());
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, cryptoFrame), Instant.now());

        // Then
        verify(connection.getSender()).send(argThat(frame -> frame instanceof ConnectionCloseFrame
                && ((ConnectionCloseFrame) frame).getErrorCode() == 0x100 + TlsConstants.AlertDescription.no_application_protocol.value),
                eq(EncryptionLevel.Initial));
    }

    @Test
    void clientHelloLackingTransportParametersExtensionLeadsToConnectionClose() throws Exception {
        // When
        List<Extension> clientExtensions = List.of(alpn);
        ClientHello ch = new ClientHello("localhost", KeyUtils.generatePublicKey(), false, clientExtensions);
        CryptoFrame cryptoFrame = new CryptoFrame(Version.getDefault(), ch.getBytes());
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, cryptoFrame), Instant.now());

        // Then
        verify(connection.getSender()).send(argThat(frame -> frame instanceof ConnectionCloseFrame
                && ((ConnectionCloseFrame) frame).getErrorCode() == 0x100 + TlsConstants.AlertDescription.missing_extension.value),
                eq(EncryptionLevel.Initial));
    }

    @Test
    void clientHelloWithCorrectTransportParametersIsAccepted() throws Exception {
        // When
        List<Extension> clientExtensions = List.of(alpn, createTransportParametersExtension());
        ClientHello ch = new ClientHello("localhost", KeyUtils.generatePublicKey(), false, clientExtensions);
        CryptoFrame cryptoFrame = new CryptoFrame(Version.getDefault(), ch.getBytes());
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, cryptoFrame), Instant.now());

        // Then
        List<Extension> serverExtensions = tlsServerEngine.getServerExtensions();
        assertThat(serverExtensions).hasAtLeastOneElementOfType(QuicTransportParametersExtension.class);
    }

    @ParameterizedTest
    @MethodSource("provideTransportParametersWithInvalidValue")
    void whenTransportParametersContainsInvalidValueServerShouldCloseConnection(TransportParameters tp) throws Exception {
        // When
        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault(), tp, Role.Client);
        List<Extension> clientExtensions = List.of(alpn, transportParametersExtension);
        ClientHello ch = new ClientHello("localhost", KeyUtils.generatePublicKey(), false, clientExtensions);
        CryptoFrame cryptoFrame = new CryptoFrame(Version.getDefault(), ch.getBytes());
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, cryptoFrame), Instant.now());

        // Then
        verify(connection.getSender()).send(argThat(frame -> frame instanceof ConnectionCloseFrame
                && ((ConnectionCloseFrame) frame).getErrorCode() == 0x08),
                eq(EncryptionLevel.Initial));
    }

    @Test
    void serverShouldSendAlpnAndQuicTransportParameterExtensions() throws Exception {
        // When
        List<Extension> clientExtensions = List.of(alpn, createTransportParametersExtension());
        ClientHello ch = new ClientHello("localhost", KeyUtils.generatePublicKey(), false, clientExtensions);
        CryptoFrame cryptoFrame = new CryptoFrame(Version.getDefault(), ch.getBytes());
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, cryptoFrame), Instant.now());

        // Then
        TlsServerEngine tlsEngine = (TlsServerEngine) new FieldReader(connection, connection.getClass().getDeclaredField("tlsEngine")).read();
        assertThat(tlsEngine.getServerExtensions()).hasAtLeastOneElementOfType(ApplicationLayerProtocolNegotiationExtension.class);
        assertThat(tlsEngine.getServerExtensions()).hasAtLeastOneElementOfType(QuicTransportParametersExtension.class);
    }

    @Test
    void messageWithOriginalDestinationCidIsProcessedOnlyOnce() throws Exception {
        byte[] odcid = new byte[] { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08 };
        CryptoFrame firstFrame = mock(CryptoFrame.class);
        CryptoFrame secondFrame = mock(CryptoFrame.class);
        InitialPacket packet1 = new InitialPacket(Version.getDefault(), new byte[8], odcid, null, firstFrame);
        InitialPacket packet2 = new InitialPacket(Version.getDefault(), new byte[8], odcid, null, secondFrame);
        connection.process(packet1, Instant.now());
        connection.process(packet2, Instant.now());

        verify(firstFrame).accept(any(FrameProcessor3.class), any(QuicPacket.class), any(Instant.class));
        verify(secondFrame, never()).accept(any(FrameProcessor3.class), any(QuicPacket.class), any(Instant.class));
    }

    static Stream<TransportParameters> provideTransportParametersWithInvalidValue() {
        TransportParameters invalidMaxStreamsBidi = createDefaultTransportParameters();
        invalidMaxStreamsBidi.setInitialMaxStreamsBidi(0x1000000000000001l);

        TransportParameters invalidMaxUdpPayloadSize = createDefaultTransportParameters();
        invalidMaxUdpPayloadSize.setMaxUdpPayloadSize(1199);

        TransportParameters invalidAckDelayExponent = createDefaultTransportParameters();
        invalidAckDelayExponent.setAckDelayExponent(21);

        TransportParameters invalidMaxAckDelay = createDefaultTransportParameters();
        invalidMaxAckDelay.setMaxAckDelay(0x4001);  // 2^14 + 1

        TransportParameters invalidActiveConnectionIdLimit = createDefaultTransportParameters();
        invalidActiveConnectionIdLimit.setActiveConnectionIdLimit(1);

        TransportParameters incorrectInitialSourceConnectionId = createDefaultTransportParameters();
        incorrectInitialSourceConnectionId.setInitialSourceConnectionId(new byte[] { 0, 0, 7, 0, 0, 0, 0, 0 });

        return Stream.of(invalidMaxStreamsBidi, invalidMaxUdpPayloadSize, invalidAckDelayExponent, invalidMaxAckDelay,
                invalidActiveConnectionIdLimit, incorrectInitialSourceConnectionId);
    }

    private ServerConnection createServerConnection(TlsServerEngineFactory tlsServerEngineFactory) throws Exception {
        byte[] odcid = new byte[] { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08 };
        ServerConnection connection = new ServerConnection(Version.getDefault(), mock(DatagramSocket.class),
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 6000), new byte[8], new byte[8], odcid,
                tlsServerEngineFactory, 100, cid -> {}, mock(Logger.class));
        SenderImpl sender = mock(SenderImpl.class);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        return connection;
    }

    private TlsServerEngineFactory createTlsServerEngine() {
        TlsServerEngineFactory tlsServerEngineFactory = mock(TlsServerEngineFactory.class);

        when(tlsServerEngineFactory.createServerEngine(any(ServerMessageSender.class), any(TlsStatusEventHandler.class))).then(new Answer<TlsServerEngine>() {
            @Override
            public TlsServerEngine answer(InvocationOnMock invocation) throws Throwable {
                tlsServerEngine = new MockTlsServerEngine(null, null, invocation.getArgument(0), invocation.getArgument(1));
                return tlsServerEngine;
            }
        });
        return tlsServerEngineFactory;
    }

    private static TransportParameters createDefaultTransportParameters() {
        TransportParameters tp = new TransportParameters();
        tp.setInitialSourceConnectionId(new byte[8]);
        return tp;
    }

    private QuicTransportParametersExtension createTransportParametersExtension() {
        return new QuicTransportParametersExtension(Version.getDefault(), createDefaultTransportParameters(), Role.Client);
    }

    static class MockTlsServerEngine extends TlsServerEngine {

        private Supplier<TlsProtocolException> exceptionSupplier;

        public MockTlsServerEngine(X509Certificate serverCertificate, PrivateKey certificateKey, ServerMessageSender serverMessageSender, TlsStatusEventHandler tlsStatusHandler) {
            super(serverCertificate, certificateKey, serverMessageSender, tlsStatusHandler);
        }

        @Override
        public void received(ClientHello clientHello) throws TlsProtocolException, IOException {
            if (exceptionSupplier != null) {
                throw exceptionSupplier.get();
            }
            statusHandler.extensionsReceived(clientHello.getExtensions());
        }

        public void injectErrorInReceivingClientHello(Supplier<TlsProtocolException> exceptionSupplier) {
            this.exceptionSupplier = exceptionSupplier;
        }
    }
}