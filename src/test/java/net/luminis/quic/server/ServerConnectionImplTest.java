/*
 * Copyright © 2021, 2022, 2023 Peter Doornbosch
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

import net.luminis.quic.*;
import net.luminis.quic.KeyUtils;
import net.luminis.quic.Version;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.frame.FrameProcessor;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.packet.HandshakePacket;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.packet.RetryPacket;
import net.luminis.quic.stream.StreamManager;
import net.luminis.quic.test.FieldReader;
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
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import net.luminis.quic.test.FieldSetter;
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

import static net.luminis.quic.QuicConstants.TransportParameterId.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;


class ServerConnectionImplTest {

    public static final String DEFAULT_APPLICATION_PROTOCOL = "hq-29";
    private ServerConnectionImpl connection;
    private ApplicationLayerProtocolNegotiationExtension alpn = new ApplicationLayerProtocolNegotiationExtension(DEFAULT_APPLICATION_PROTOCOL);
    private TlsServerEngine tlsServerEngine;
    private TlsServerEngineFactory tlsServerEngineFactory;

    @BeforeEach
    void setupObjectUnderTest() throws Exception {
        tlsServerEngineFactory = createTlsServerEngine();
        connection = createServerConnection(tlsServerEngineFactory, false, new byte[8]);
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
                List.of(TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256), List.of(TlsConstants.SignatureScheme.rsa_pss_pss_sha256), TlsConstants.NamedGroup.secp256r1, clientExtensions, null, ClientHello.PskKeyEstablishmentMode.both);
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

    @ParameterizedTest
    @MethodSource("provideInvalidTransportParametersForClient")
    void whenTransportParametersContainsInvalidParameterServerShouldCloseConnection(TransportParameters tp) throws Exception {
        // When
        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtensionTest(tp);
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
    void versionInformationWithSupportedOtherVersionLeadsToVersionChange() throws Exception {
        var connectionSecrets = spyOnConnectionSecrets();

        // Given
        TransportParameters.VersionInformation versionInfo = new TransportParameters.VersionInformation(Version.QUIC_version_1, List.of(Version.QUIC_version_2, Version.QUIC_version_1));
        List<Extension> clientExtensions = List.of(alpn, createTransportParametersExtension(versionInfo));
        ClientHello ch = new ClientHello("localhost", KeyUtils.generatePublicKey(), false, clientExtensions);
        CryptoFrame cryptoFrame = new CryptoFrame(Version.QUIC_version_1, ch.getBytes());

        // When
        connection.process(new InitialPacket(Version.QUIC_version_1, new byte[8], new byte[8], null, cryptoFrame), Instant.now());

        // Then
        assertThat(connection.getQuicVersion().equals(Version.QUIC_version_2));
        verify(connectionSecrets).recomputeInitialKeys();
    }

    @Test
    void versionInformationWithoutSupportedOtherVersionLeadsToNoVersionChange() throws Exception {
        var connectionSecrets = spyOnConnectionSecrets();

        // Given
        TransportParameters.VersionInformation versionInfo = new TransportParameters.VersionInformation(Version.QUIC_version_1, List.of(Version.parse(0x1a2a3a4a), Version.QUIC_version_1));
        List<Extension> clientExtensions = List.of(alpn, createTransportParametersExtension(versionInfo));
        ClientHello ch = new ClientHello("localhost", KeyUtils.generatePublicKey(), false, clientExtensions);
        CryptoFrame cryptoFrame = new CryptoFrame(Version.QUIC_version_1, ch.getBytes());

        // When
        connection.process(new InitialPacket(Version.QUIC_version_1, new byte[8], new byte[8], null, cryptoFrame), Instant.now());

        // Then
        assertThat(connection.getQuicVersion().equals(Version.QUIC_version_1));
        verify(connectionSecrets, never()).recomputeInitialKeys();
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
        connection = createServerConnection(tlsServerEngineFactory, false, odcid);
        CryptoFrame firstFrame = mock(CryptoFrame.class);
        CryptoFrame secondFrame = mock(CryptoFrame.class);
        InitialPacket packet1 = new InitialPacket(Version.getDefault(), new byte[8], odcid, null, firstFrame);
        InitialPacket packet2 = new InitialPacket(Version.getDefault(), new byte[8], odcid, null, secondFrame);
        connection.process(packet1, Instant.now());
        connection.process(packet2, Instant.now());

        verify(firstFrame).accept(any(FrameProcessor.class), any(QuicPacket.class), any(Instant.class));
        verify(secondFrame).accept(any(FrameProcessor.class), any(QuicPacket.class), any(Instant.class));
    }

    @Test
    void newServerConnectionUsesOriginalScidAsDcid() throws Exception {
        byte[] clientSourceCid = new byte[] { 0x03, 0x07, 0x05, 0x01 };
        byte[] odcid = new byte[] { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08 };

        // When
        connection = createServerConnection(tlsServerEngineFactory, false, clientSourceCid, odcid, cid -> {});

        // Then
        assertThat(connection.getDestinationConnectionId()).isEqualTo(clientSourceCid);
    }

    @Test
    void whenRetryIsRequiredFirstInitialLeadsToRetryPacket() throws Exception {
        // Given
        connection = createServerConnection(createTlsServerEngine(), true, new byte[8]);

        // When
        connection.process(new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, new CryptoFrame()), Instant.now());

        // Then
        verify(connection.getSender()).send(any(RetryPacket.class));
    }

    @Test
    void whenRetryIsRequiredAllRetryPacketsContainsSameToken() throws Exception {
        // Given
        connection = createServerConnection(createTlsServerEngine(), true, new byte[8]);
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
        ServerConnectionImpl connection1 = createServerConnection(createTlsServerEngine(), true, dcid1);
        connection1.process(new InitialPacket(Version.getDefault(), new byte[8], dcid1, null, new CryptoFrame()), Instant.now());
        ArgumentCaptor<RetryPacket> argumentCaptor = ArgumentCaptor.forClass(RetryPacket.class);
        verify(connection1.getSender()).send(argumentCaptor.capture());
        byte[] retryToken = argumentCaptor.getValue().getRetryToken();

        // When
        byte[] dcid2 = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1, 0 };
        ServerConnectionImpl connection2 = createServerConnection(createTlsServerEngine(), true, dcid2);
        connection2.process(new InitialPacket(Version.getDefault(), new byte[8], dcid2, null, new CryptoFrame()), Instant.now());

        // Then
        verify(connection2.getSender()).send(argThat(retryPacket -> !Arrays.equals(retryPacket.getRetryToken(), retryToken)));
    }

    @Test
    void whenRetryIsRequiredInitialWithTokenIsProcessed() throws Exception {
        // Given
        connection = createServerConnection(createTlsServerEngine(), true, null);
        connection = createServerConnection(createTlsServerEngine(), true, new byte[8]);
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
        connection = createServerConnection(createTlsServerEngine(), true, new byte[8]);
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
        connection = createServerConnection(createTlsServerEngine(), true, odcid);
        InitialPacket initialPacket = new InitialPacket(Version.getDefault(), new byte[8], odcid, null, new CryptoFrame(Version.getDefault(), new byte[38]));
        initialPacket.setPacketNumber(0);
        ConnectionSecrets clientConnectionSecrets = new ConnectionSecrets(VersionHolder.withDefault(), Role.Client, null, mock(Logger.class));
        clientConnectionSecrets.computeInitialKeys(odcid);
        byte[] initialPacketBytes = initialPacket.generatePacketBytes(clientConnectionSecrets.getClientAead(EncryptionLevel.Initial));
        ByteBuffer paddedInitial = ByteBuffer.allocate(1200);
        paddedInitial.put(initialPacketBytes);

        connection.parseAndProcessPackets(0, Instant.now(), paddedInitial, null);
        ArgumentCaptor<RetryPacket> argumentCaptor1 = ArgumentCaptor.forClass(RetryPacket.class);
        verify(connection.getSender()).send(argumentCaptor1.capture());
        byte[] retryPacket1 = argumentCaptor1.getValue().generatePacketBytes(null);
        clearInvocations(connection.getSender());

        // When
        connection.parseAndProcessPackets(0, Instant.now(), paddedInitial, null);
        ArgumentCaptor<RetryPacket> argumentCaptor2 = ArgumentCaptor.forClass(RetryPacket.class);
        verify(connection.getSender()).send(argumentCaptor2.capture());
        RetryPacket retryPacket2 = argumentCaptor1.getValue();

        // Then
        assertThat(retryPacket1).isEqualTo(retryPacket2.generatePacketBytes(null));
    }

    @Test
    void whenServerConnectionIsAbortedCloseCallbackShouldBeCalled() throws Exception {
        // Given
        byte[] odcid = { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08 };
        AtomicBoolean closeCallbackIsCalled = new AtomicBoolean(false);
        connection = createServerConnection(createTlsServerEngine(), true, new byte[8], odcid, cid -> closeCallbackIsCalled.set(true));

        // When
        connection.abortConnection(new RuntimeException("injected error"));

        // Then
        assertThat(closeCallbackIsCalled.get()).isTrue();
    }

    @Test
    void receivingInitialPacketShouldSetAntiAmplification() throws Exception {
        // Given
        byte[] odcid = ByteUtils.hexToBytes("67268378ae7dc13b");
        connection = createServerConnection(tlsServerEngineFactory, false, odcid);

        // When
        byte[] validInitial = TestUtils.createValidInitial(Version.getDefault());
        connection.parseAndProcessPackets(0, Instant.now(), ByteBuffer.wrap(validInitial), null);
        ArgumentCaptor<Integer> antiAmplificationLimitCaptor = ArgumentCaptor.forClass(Integer.class);

        // Then
        verify(connection.getSender()).setAntiAmplificationLimit(antiAmplificationLimitCaptor.capture());
        assertThat(antiAmplificationLimitCaptor.getValue()).isEqualTo(3 * validInitial.length);
    }

    @Test
    void receivingInvalidInitialPacketShouldAddToAntiAmplificationLimit() throws Exception {
        // When
        byte[] invalidInitial = TestUtils.createInvalidInitial(Version.getDefault());
        connection.parseAndProcessPackets(0, Instant.now(), ByteBuffer.wrap(invalidInitial), null);

        // Then
        ArgumentCaptor<Integer> antiAmplificationLimitCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(connection.getSender()).setAntiAmplificationLimit(antiAmplificationLimitCaptor.capture());
        assertThat(antiAmplificationLimitCaptor.getValue()).isEqualTo(3 * invalidInitial.length);
    }

    @Test
    void whenPeerAddressValidatedAntiAmplificationIsDisabled() {
        // When
        connection.process(new HandshakePacket(Version.getDefault(), new byte[0], new byte[0], new CryptoFrame(Version.getDefault(), new byte[300])), Instant.now());

        // Then
        verify(connection.getSender()).unsetAntiAmplificationLimit();
    }

    @Test
    void whenRetryIsRequiredInitialWithValidTokenDisablesAntiAmplificationLimit() throws Exception {
        // Given
        connection = createServerConnection(createTlsServerEngine(), true, new byte[8]);
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
        verify(connection.getSender()).unsetAntiAmplificationLimit();
    }

    @Test
    void initialPacketCarriedInDatagramSmallerThan1200BytesShouldBeDropped() throws Exception {
        // Given
        byte[] initialPacketBytes = TestUtils.createValidInitialNoPadding(Version.getDefault());
        byte[] odcid = Arrays.copyOfRange(initialPacketBytes, 6, 6 + 8);
        connection = createServerConnection(tlsServerEngineFactory, false, odcid);

        // When
        connection.parseAndProcessPackets(0, Instant.now(), ByteBuffer.wrap(initialPacketBytes), null);

        // Then
        verify(connection.getSender(), never()).send(any(QuicFrame.class), any(EncryptionLevel.class));
    }

    @Test
    void initialPacketWithPaddingInDatagramShouldBeAccepted() throws Exception {
        // Given
        byte[] initialPacketBytes = TestUtils.createValidInitialNoPadding(Version.getDefault());
        byte[] odcid = Arrays.copyOfRange(initialPacketBytes, 6, 6 + 8);
        connection = createServerConnection(tlsServerEngineFactory, false, odcid);

        // When
        ByteBuffer buffer = ByteBuffer.allocate(1200);
        buffer.put(initialPacketBytes);
        connection.parseAndProcessPackets(0, Instant.now(), buffer, null);

        // Then
        verify(connection.getSender(), atLeastOnce()).send(any(QuicFrame.class), any(EncryptionLevel.class));
    }

    @Test
    void whenInitialPacketPaddedInDatagramAllBytesShouldBeCountedInAntiAmplificationLimit() throws Exception {
        // Given
        byte[] initialPacketBytes = TestUtils.createValidInitialNoPadding(Version.getDefault());
        byte[] odcid = Arrays.copyOfRange(initialPacketBytes, 6, 6 + 8);
        connection = createServerConnection(tlsServerEngineFactory, false, odcid);

        // When
        ByteBuffer buffer = ByteBuffer.allocate(1200);
        buffer.put(initialPacketBytes);
        connection.parseAndProcessPackets(0, Instant.now(), buffer, null);

        // Then
        ArgumentCaptor<Integer> antiAmplicationLimitCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(connection.getSender()).setAntiAmplificationLimit(antiAmplicationLimitCaptor.capture());
        assertThat(antiAmplicationLimitCaptor.getValue()).isEqualTo(3 * 1200);
    }

    @Test
    void whenParsingZeroRttPacketItShouldFailOnMissingKeys() throws Exception {
        // Given
        byte[] data = { (byte) 0b11010001, 0x00, 0x00, 0x00, 0x01, 0, 0, 17, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        assertThatThrownBy(() ->
                // When
                connection.parsePacket(ByteBuffer.wrap(data))
        )
                // Then
                .isInstanceOf(MissingKeysException.class)
                .hasMessageContaining("ZeroRTT");
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

    static Stream<TransportParameters> provideInvalidTransportParametersForClient() {
        TransportParameters withOriginalDestinationConnectionId = createDefaultTransportParameters();
        withOriginalDestinationConnectionId.setOriginalDestinationConnectionId(new byte[8]);

        TransportParameters withPreferredAddress = createDefaultTransportParameters();
        withPreferredAddress.setPreferredAddress(new TransportParameters.PreferredAddress());

        TransportParameters withRetrySourceConnectionId = createDefaultTransportParameters();
        withRetrySourceConnectionId.setRetrySourceConnectionId(new byte[8]);

        TransportParameters withStatelessResetToken = createDefaultTransportParameters();
        withStatelessResetToken.setStatelessResetToken(new byte[16]);

        return Stream.of(withOriginalDestinationConnectionId, withPreferredAddress, withRetrySourceConnectionId, withStatelessResetToken);
    }

    private ServerConnectionImpl createServerConnection(TlsServerEngineFactory tlsServerEngineFactory, boolean retryRequired, byte[] odcid) throws Exception {
        if (odcid == null) {
            odcid = new byte[]{ 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08 };
        }
        return createServerConnection(tlsServerEngineFactory, retryRequired, new byte[8], odcid, cid -> {});
    }

    private ServerConnectionImpl createServerConnection(TlsServerEngineFactory tlsServerEngineFactory, boolean retryRequired, byte[] clientCid, byte[] odcid, Consumer<ServerConnectionImpl> closeCallback) throws Exception {
        ApplicationProtocolRegistry applicationProtocolRegistry = new ApplicationProtocolRegistry();
        applicationProtocolRegistry.registerApplicationProtocol("hq-29", mock(ApplicationProtocolConnectionFactory.class));

        ServerConnectionImpl connection = new ServerConnectionImpl(Version.getDefault(), mock(DatagramSocket.class),
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 6000), clientCid, odcid,
                8, tlsServerEngineFactory, retryRequired, applicationProtocolRegistry, 100, null, closeCallback, mock(Logger.class));

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

    private QuicTransportParametersExtension createTransportParametersExtension(TransportParameters.VersionInformation versionInfo) {
        TransportParameters transportParameters = createDefaultTransportParameters();
        transportParameters.setVersionInformation(versionInfo);
        return new QuicTransportParametersExtension(Version.getDefault(), transportParameters, Role.Client);
    }

    private ConnectionSecrets spyOnConnectionSecrets() throws Exception {
        ConnectionSecrets connectionSecrets = spy((ConnectionSecrets) new FieldReader(connection, QuicConnectionImpl.class.getDeclaredField("connectionSecrets")).read());
        FieldSetter.setField(connection, QuicConnectionImpl.class. getDeclaredField("connectionSecrets"), connectionSecrets);
        return connectionSecrets;
    }

    static class MockTlsServerEngine extends TlsServerEngine {

        private Supplier<TlsProtocolException> exceptionSupplier;

        public MockTlsServerEngine(X509Certificate serverCertificate, PrivateKey certificateKey, ServerMessageSender serverMessageSender, TlsStatusEventHandler tlsStatusHandler) {
            super(serverCertificate, certificateKey, serverMessageSender, tlsStatusHandler, null);
        }

        @Override
        public void received(ClientHello clientHello, ProtectionKeysType keyType) throws TlsProtocolException, IOException {
            if (exceptionSupplier != null) {
                throw exceptionSupplier.get();
            }
            statusHandler.extensionsReceived(clientHello.getExtensions());
        }

        public void injectErrorInReceivingClientHello(Supplier<TlsProtocolException> exceptionSupplier) {
            this.exceptionSupplier = exceptionSupplier;
        }
    }

    /**
     * For testing behaviour when invalid parameters are sent (for client or server), the serialize method must be
     * overridden, because the original will check for each parameter whether it is valid to sent for the given role.
     */
    static class QuicTransportParametersExtensionTest extends QuicTransportParametersExtension {

        private TransportParameters transportParameters;

        QuicTransportParametersExtensionTest(TransportParameters transportParameters) {
            super(Version.getDefault(), transportParameters, Role.Client);
            this.transportParameters = transportParameters;
        }

        @Override
        protected void serialize() {
            super.serialize();

            ByteBuffer extendedBuffer = ByteBuffer.allocate(1024);
            extendedBuffer.put(getBytes());

            if (transportParameters.getOriginalDestinationConnectionId() != null) {
                addTransportParameter(extendedBuffer, original_destination_connection_id, transportParameters.getOriginalDestinationConnectionId());
            }
            if (transportParameters.getPreferredAddress() != null) {
                byte[] addressData = new byte[41];
                addressData[0] = 123;   // IP address must not be all 0
                addTransportParameter(extendedBuffer, preferred_address, addressData);
            }
            if (transportParameters.getRetrySourceConnectionId() != null) {
                addTransportParameter(extendedBuffer, retry_source_connection_id, transportParameters.getRetrySourceConnectionId());
            }
            if (transportParameters.getStatelessResetToken() != null) {
                addTransportParameter(extendedBuffer, stateless_reset_token, transportParameters.getStatelessResetToken());
            }

            int length = extendedBuffer.position();
            extendedBuffer.limit(length);

            int extensionsSize = length - 2 - 2;  // 2 bytes for the length itself and 2 for the type
            extendedBuffer.putShort(2, (short) extensionsSize);

            byte[] data = new byte[length];
            extendedBuffer.flip();
            extendedBuffer.get(data);

            FieldSetter.setField(this, QuicTransportParametersExtension.class, "data", data);
        }
    }
}