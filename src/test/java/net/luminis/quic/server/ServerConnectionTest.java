package net.luminis.quic.server;

import net.luminis.quic.*;
import net.luminis.quic.Version;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.frame.FrameProcessor3;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.packet.RetryPacket;
import net.luminis.quic.stream.StreamManager;
import net.luminis.quic.tls.QuicTransportParametersExtension;
import net.luminis.quic.frame.ConnectionCloseFrame;
import net.luminis.quic.frame.CryptoFrame;
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

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;
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
        connection = createServerConnection(tlsServerEngineFactory, false);
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
    void whenTransportParametersAreProcessedStreamManagerDefaultsShouldHaveBeenSet() throws Exception {
        // Given
        StreamManager streamManager = mock(StreamManager.class);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("streamManager"), streamManager);

        QuicTransportParametersExtension transportParametersExtension = createTransportParametersExtension();
        transportParametersExtension.getTransportParameters().setInitialMaxStreamsUni(3);
        transportParametersExtension.getTransportParameters().setInitialMaxStreamsBidi(100);
        List<Extension> clientExtensions = List.of(alpn, transportParametersExtension);
        ClientHello ch = new ClientHello("localhost", KeyUtils.generatePublicKey(), false, clientExtensions);
        CryptoFrame cryptoFrame = new CryptoFrame(Version.getDefault(), ch.getBytes());

        // When
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, cryptoFrame), Instant.now());

        // Then
        verify(streamManager).setInitialMaxStreamsUni(longThat(value -> value == 3));
        verify(streamManager).setInitialMaxStreamsBidi(longThat(value -> value == 100));
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
    void serverShouldSendTransportParameterDisableActiveMigration() throws Exception {
        // When
        List<Extension> clientExtensions = List.of(alpn, createTransportParametersExtension());
        ClientHello ch = new ClientHello("localhost", KeyUtils.generatePublicKey(), false, clientExtensions);
        CryptoFrame cryptoFrame = new CryptoFrame(Version.getDefault(), ch.getBytes());
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, cryptoFrame), Instant.now());

        // Then
        TlsServerEngine tlsEngine = (TlsServerEngine) new FieldReader(connection, connection.getClass().getDeclaredField("tlsEngine")).read();
        assertThat(tlsEngine.getServerExtensions()).hasAtLeastOneElementOfType(QuicTransportParametersExtension.class);
        QuicTransportParametersExtension tpExtension = (QuicTransportParametersExtension) tlsEngine.getServerExtensions().stream().filter(ext -> ext instanceof QuicTransportParametersExtension).findFirst().get();
        assertThat(tpExtension.getTransportParameters().getDisableMigration()).isTrue();
    }

    @Test
    void retransmittedOriginalInitialMessageIsProcessedToo() throws Exception {
        byte[] odcid = new byte[] { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08 };
        CryptoFrame firstFrame = mock(CryptoFrame.class);
        CryptoFrame secondFrame = mock(CryptoFrame.class);
        InitialPacket packet1 = new InitialPacket(Version.getDefault(), new byte[8], odcid, null, firstFrame);
        InitialPacket packet2 = new InitialPacket(Version.getDefault(), new byte[8], odcid, null, secondFrame);
        connection.process(packet1, Instant.now());
        connection.process(packet2, Instant.now());

        verify(firstFrame).accept(any(FrameProcessor3.class), any(QuicPacket.class), any(Instant.class));
        verify(secondFrame).accept(any(FrameProcessor3.class), any(QuicPacket.class), any(Instant.class));
    }

    @Test
    void whenRetryIsRequiredFirstInitialLeadsToRetryPacket() throws Exception {
        // Given
        connection = createServerConnection(createTlsServerEngine(), true);

        // When
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, new CryptoFrame()), Instant.now());

        // Then
        verify(connection.getSender()).send(any(RetryPacket.class));
    }

    @Test
    void whenRetryIsRequiredAllRetryPacketsContainsSameToken() throws Exception {
        // Given
        connection = createServerConnection(createTlsServerEngine(), true);
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, new CryptoFrame()), Instant.now());
        ArgumentCaptor<RetryPacket> argumentCaptor = ArgumentCaptor.forClass(RetryPacket.class);
        verify(connection.getSender()).send(argumentCaptor.capture());
        byte[] retryToken = argumentCaptor.getValue().getRetryToken();
        clearInvocations(connection.getSender());
        // When
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, new CryptoFrame()), Instant.now());

        // Then
        verify(connection.getSender()).send(argThat(retryPacket -> Arrays.equals(retryPacket.getRetryToken(), retryToken)));
    }

    @Test
    void whenRetryIsRequiredDifferentDestinationConnectionIdsGetDifferentToken() throws Exception {
        // Given
        byte[] dcid1 = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
        ServerConnection connection1 = createServerConnection(createTlsServerEngine(), dcid1,true, cid -> {});
        connection1.process(new InitialPacket(Version.getDefault(), new byte[8], dcid1, null, new CryptoFrame()), Instant.now());
        ArgumentCaptor<RetryPacket> argumentCaptor = ArgumentCaptor.forClass(RetryPacket.class);
        verify(connection1.getSender()).send(argumentCaptor.capture());
        byte[] retryToken = argumentCaptor.getValue().getRetryToken();

        // When
        byte[] dcid2 = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1, 0 };
        ServerConnection connection2 = createServerConnection(createTlsServerEngine(), dcid2, true, cid -> {});
        connection2.process(new InitialPacket(Version.getDefault(), new byte[8], dcid2, null, new CryptoFrame()), Instant.now());

        // Then
        verify(connection2.getSender()).send(argThat(retryPacket -> !Arrays.equals(retryPacket.getRetryToken(), retryToken)));
    }

    @Test
    void whenRetryIsRequiredInitialWithTokenIsProcessed() throws Exception {
        // Given
        connection = createServerConnection(createTlsServerEngine(), true);
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, new CryptoFrame()), Instant.now());
        ArgumentCaptor<RetryPacket> argumentCaptor = ArgumentCaptor.forClass(RetryPacket.class);
        verify(connection.getSender()).send(argumentCaptor.capture());
        byte[] retryToken = argumentCaptor.getValue().getRetryToken();
        clearInvocations(connection.getSender());

        // When
        ClientHello ch = new ClientHello("testserver", KeyUtils.generatePublicKey(), false, Collections.emptyList());
        CryptoFrame initialCrypto = new CryptoFrame(Version.getDefault(), ch.getBytes());
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], retryToken, initialCrypto), Instant.now());

        // Then
        verify(connection.getSender()).send(argThat(frame -> frame instanceof ConnectionCloseFrame
                && ((ConnectionCloseFrame) frame).getErrorCode() == 256 + TlsConstants.AlertDescription.missing_extension.value), any(EncryptionLevel.class));
    }

    @Test
    void whenRetryIsRequiredInitialWithInvalidTokenConnectionIsClosed() throws Exception {
        // Given
        connection = createServerConnection(createTlsServerEngine(), true);
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, new CryptoFrame()), Instant.now());
        ArgumentCaptor<RetryPacket> argumentCaptor = ArgumentCaptor.forClass(RetryPacket.class);
        verify(connection.getSender()).send(argumentCaptor.capture());
        byte[] retryToken = argumentCaptor.getValue().getRetryToken();
        byte[] incorrectToken = Arrays.copyOfRange(retryToken, 0, retryToken.length - 1);

        // When
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], incorrectToken, new CryptoFrame()), Instant.now());

        // Then
        verify(connection.getSender()).send(argThat(frame -> frame instanceof ConnectionCloseFrame
                && ((ConnectionCloseFrame) frame).getErrorCode() == 0x0b), any(EncryptionLevel.class));
    }

    @Test
    void whenRetryIsRequiredSecondInitialShouldReturnSameRetryPacket() throws Exception {
        // Given
        byte[] odcid = { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08 };
        connection = createServerConnection(createTlsServerEngine(), odcid,true, cid -> {});
        InitialPacket initialPacket = new InitialPacket(Version.getDefault(), new byte[8], odcid, null, new CryptoFrame(Version.getDefault(), new byte[38]));
        ConnectionSecrets clientConnectionSecrets = new ConnectionSecrets(Version.getDefault(), Role.Client, null, mock(Logger.class));
        clientConnectionSecrets.computeInitialKeys(odcid);
        byte[] initialPacketBytes = initialPacket.generatePacketBytes(0L, clientConnectionSecrets.getClientSecrets(EncryptionLevel.Initial));

        connection.parsePackets(0, Instant.now(), ByteBuffer.wrap(initialPacketBytes));
        ArgumentCaptor<RetryPacket> argumentCaptor1 = ArgumentCaptor.forClass(RetryPacket.class);
        verify(connection.getSender()).send(argumentCaptor1.capture());
        byte[] retryPacket1 = argumentCaptor1.getValue().generatePacketBytes(0L, null);
        clearInvocations(connection.getSender());

        // When
        connection.parsePackets(0, Instant.now(), ByteBuffer.wrap(initialPacketBytes));
        ArgumentCaptor<RetryPacket> argumentCaptor2 = ArgumentCaptor.forClass(RetryPacket.class);
        verify(connection.getSender()).send(argumentCaptor2.capture());
        RetryPacket retryPacket2 = argumentCaptor1.getValue();

        // Then
        assertThat(retryPacket1).isEqualTo(retryPacket2.generatePacketBytes(0L, null));
    }

    @Test
    void whenServerConnectionIsAbortedCloseCallbackShouldBeCalled() throws Exception {
        // Given
        byte[] odcid = { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08 };
        AtomicBoolean closeCallbackIsCalled = new AtomicBoolean(false);
        connection = createServerConnection(createTlsServerEngine(), odcid,true, cid -> closeCallbackIsCalled.set(true));

        // When
        connection.abortConnection(new RuntimeException("injected error"));

        // Then
        assertThat(closeCallbackIsCalled.get()).isTrue();
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

    private ServerConnection createServerConnection(TlsServerEngineFactory tlsServerEngineFactory, boolean retryRequired) throws Exception {
        byte[] odcid = new byte[] { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08 };
        return createServerConnection(tlsServerEngineFactory, odcid, retryRequired, cid -> {});
    }

    private ServerConnection createServerConnection(TlsServerEngineFactory tlsServerEngineFactory, byte[] odcid, boolean retryRequired, Consumer<byte[]> closeCallback) throws Exception {
        ApplicationProtocolRegistry applicationProtocolRegistry = new ApplicationProtocolRegistry();
        applicationProtocolRegistry.registerApplicationProtocol("hq-29", mock(ApplicationProtocolConnectionFactory.class));

        ServerConnection connection = new ServerConnection(Version.getDefault(), mock(DatagramSocket.class),
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 6000), new byte[8], new byte[8], odcid,
                tlsServerEngineFactory, retryRequired, applicationProtocolRegistry, 100, closeCallback, mock(Logger.class));

        SenderImpl sender = mock(SenderImpl.class);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        return connection;
    }

    private TlsServerEngineFactory createTlsServerEngine() {
        TlsServerEngineFactory tlsServerEngineFactory = mock(TlsServerEngineFactory.class);

        when(tlsServerEngineFactory.createServerEngine(any(ServerMessageSender.class), any(TlsStatusEventHandler.class))).then(new Answer<TlsServerEngine>() {
            @Override
            public TlsServerEngine answer(InvocationOnMock invocation) throws Throwable {
                tlsServerEngine = new MockTlsServerEngine(mock(X509Certificate.class), null, invocation.getArgument(0), invocation.getArgument(1));
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