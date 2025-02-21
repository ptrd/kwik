/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.impl;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import tech.kwik.agent15.engine.TlsClientEngine;
import tech.kwik.agent15.handshake.ClientHello;
import tech.kwik.core.ConnectionConfig;
import tech.kwik.core.ConnectionListener;
import tech.kwik.core.ConnectionTerminatedEvent;
import tech.kwik.core.QuicStream;
import tech.kwik.core.cc.FixedWindowCongestionController;
import tech.kwik.core.cid.ConnectionIdInfo;
import tech.kwik.core.cid.ConnectionIdManager;
import tech.kwik.core.cid.ConnectionIdStatus;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.frame.*;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.packet.*;
import tech.kwik.core.send.SenderImpl;
import tech.kwik.core.stream.StreamManager;
import tech.kwik.core.test.ByteUtils;
import tech.kwik.core.test.FieldReader;
import tech.kwik.core.test.FieldSetter;
import tech.kwik.core.test.TestClock;
import tech.kwik.core.test.TestScheduledExecutor;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static tech.kwik.agent15.TlsConstants.NamedGroup.secp256r1;
import static tech.kwik.core.QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR;
import static tech.kwik.core.QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR;

class QuicClientConnectionImplTest {

    private static Logger logger;
    private final byte[] destinationConnectionId = { 0x00, 0x01, 0x02, 0x03 };

    private QuicClientConnectionImpl connection;
    private byte[] originalDestinationId;
    private SenderImpl sender;
    private TlsClientEngine tlsClientEngine;
    private TestScheduledExecutor testScheduledExecutor;

    //region setup
    @BeforeAll
    static void initLogger() {
        logger = new NullLogger();
    }

    @BeforeEach
    void initConnectionUnderTest() throws Exception {
        connection = (QuicClientConnectionImpl) QuicClientConnectionImpl.newBuilder()
                .connectTimeout(Duration.ofSeconds(1))
                .connectionIdLength(4)
                .uri(new URI("//localhost:443"))
                .applicationProtocol("hq-interop")
                .logger(logger).build();
        FieldSetter.setField(connection, "parser", mock(ClientRolePacketParser.class));
        sender = Mockito.mock(SenderImpl.class);
        var connectionIdManager = new FieldReader(connection, connection.getClass().getDeclaredField("connectionIdManager")).read();
        FieldSetter.setField(connectionIdManager, "sender", sender);
        FieldSetter.setField(connection, "sender", sender);

        testScheduledExecutor = new TestScheduledExecutor(new TestClock());
        FieldSetter.setField(connection, QuicConnectionImpl.class, "callbackThread", testScheduledExecutor);
    }
    //endregion

    //region initial packet
    @Test
    void initialWithTokenShouldBeDiscarded() {
        // When
        byte[] token = new byte[16];
        PacketProcessor.ProcessResult result = connection.process(new InitialPacket(Version.getDefault(), destinationConnectionId, new byte[0], token, new PingFrame()), null);

        // Then
        assertThat(result).isEqualTo(PacketProcessor.ProcessResult.Abort);
    }
    //endregion

    //region retry
    @Test
    void testRetryPacketInitiatesInitialPacketWithToken() throws Exception {
        simulateSuccessfulConnect();

        byte[] originalConnectionId = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
        // By using a fixed value for the original destination connection, the integrity tag will also have a fixed value, which simplifies the test
        setFixedOriginalDestinationConnectionId(originalConnectionId);

        // First InitialPacket should not contain a token.
        verify(sender, never()).setInitialToken(any(byte[].class));

        // Simulate a RetryPacket is received
        RetryPacket retryPacket = createRetryPacket(originalConnectionId, "9442e0ac29f6d650adc5e4b4a3cd12cc");
        connection.process(retryPacket, null);

        // A second InitialPacket should be send with token
        verify(sender).setInitialToken(
                argThat(token -> token != null && Arrays.equals(token, new byte[] { 0x01, 0x02, 0x03 })));
    }

    @Test
    void testSecondRetryPacketShouldBeIgnored() throws Exception {
        simulateSuccessfulConnect();

        byte[] originalConnectionId = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
        // By using a fixed value for the original destination connection, the integrity tag will also have a fixed value, which simplifies the test
        setFixedOriginalDestinationConnectionId(originalConnectionId);

        // Simulate a first RetryPacket is received
        RetryPacket retryPacket = createRetryPacket(connection.getDestinationConnectionId(), "5e5f918434a24d4b601745b4f0db7908");
        connection.process(retryPacket, null);

        clearInvocations(sender);

        // Simulate a second RetryPacket is received
        RetryPacket secondRetryPacket = createRetryPacket(connection.getDestinationConnectionId(), "00f4bbc72790b7c7947f86ec9fb0a68d");
        connection.process(secondRetryPacket, null);

        verify(sender, never()).send(any(QuicFrame.class), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void testRetryPacketWithIncorrectOriginalDestinationIdShouldBeDiscarded() throws Exception {
        simulateSuccessfulConnect();

        // Simulate a RetryPacket with arbitrary original destination id is received
        RetryPacket retryPacket = createRetryPacket(new byte[] { 0x03, 0x0a, 0x0d, 0x09 }, "00112233445566778899aabbccddeeff");
        connection.process(retryPacket, null);

        verify(sender, never()).send(any(QuicFrame.class), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void testAfterRetryPacketTransportParametersWithoutOriginalDestinationIdLeadsToConnectionError() throws Exception {
        simulateConnectionReceivingRetryPacket();
        connection = spy(connection);

        // Simulate a TransportParametersExtension is received that does not contain the right original destination id
        connection.setPeerTransportParameters(new TransportParameters());

        ArgumentCaptor<Long> errorCaptor = ArgumentCaptor.forClass(Long.class);
        verify(connection).immediateCloseWithError(errorCaptor.capture(), any(), any());
        assertThat(errorCaptor.getValue()).isEqualTo(TRANSPORT_PARAMETER_ERROR.value);
    }

    @Test
    void testAfterRetryPacketTransportParametersWithIncorrectOriginalDestinationIdLeadsToConnectionError() throws Exception {
        RetryPacket retryPacket = simulateConnectionReceivingRetryPacket();
        connection = spy(connection);

        // Simulate a TransportParametersExtension is received that...
        TransportParameters transportParameters = new TransportParameters();
        // - has the server's source cid (because the test stops after "sending" the retry-packet, this is not the "final" server source cid, but the one used in the retry packet)
        transportParameters.setInitialSourceConnectionId(retryPacket.getSourceConnectionId());
        // - does contain the original destination id
        transportParameters.setOriginalDestinationConnectionId(originalDestinationId);
        // -  does contain an original destination id (but incorrect)
        transportParameters.setRetrySourceConnectionId(new byte[] { 0x0d, 0x0d, 0x0d, 0x0d });

        // When
        assertThatThrownBy(() -> connection.setPeerTransportParameters(transportParameters)
                // Then
        ).isInstanceOf(TransportError.class);
    }

    @Test
    void testAfterRetryPacketTransportParametersWithCorrectRetrySourceConnectionId() throws Exception {
        RetryPacket retryPacket = simulateConnectionReceivingRetryPacket();
        connection = spy(connection);

        // Simulate a TransportParametersExtension is received that...
        TransportParameters transportParameters = new TransportParameters();
        // - has the server's source cid (because the test stops after "sending" the retry-packet, this is not the "final" server source cid, but the one used in the retry packet)
        transportParameters.setInitialSourceConnectionId(retryPacket.getSourceConnectionId());
        // - does contain the original destination id
        transportParameters.setOriginalDestinationConnectionId(originalDestinationId);
        // - sets the retry cid to the source cid of the retry packet
        transportParameters.setRetrySourceConnectionId(retryPacket.getSourceConnectionId());
        connection.setPeerTransportParameters(transportParameters);

        verify(connection, never()).immediateCloseWithError(anyInt(), anyString());
    }

    @Test
    void processingRetryPacketShouldNotRestartTlsEngine() throws Exception {
        // When
        simulateConnectionReceivingRetryPacket();

        // Then
        verify(tlsClientEngine, never()).startHandshake();
    }

    @Test
    void testWithNormalConnectionTransportParametersShouldNotContainRetrySourceId() throws Exception {
        byte[] originalSourceConnectionId = new byte[] { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
        setFixedOriginalDestinationConnectionId(originalSourceConnectionId);
        simulateSuccessfulConnect();
        connection = spy(connection);

        // Simulate a TransportParametersExtension is received that does not contain a retry source id
        TransportParameters transportParameters = new TransportParameters();
        // But it must contain
        transportParameters.setInitialSourceConnectionId(connection.getDestinationConnectionId());
        transportParameters.setOriginalDestinationConnectionId(originalSourceConnectionId);
        connection.setPeerTransportParameters(transportParameters);

        verify(connection, never()).immediateCloseWithError(anyInt(), anyString());
    }

    @Test
    void testOnNormalConnectionTransportParametersWithOriginalDestinationIdLeadsToConnectionError() throws Exception {
        simulateSuccessfulConnect();
        connection = spy(connection);

        // Simulate a TransportParametersExtension is received that does contain an original destination id
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setRetrySourceConnectionId(new byte[] { 0x0d, 0x0d, 0x0d, 0x0d });
        connection.setPeerTransportParameters(transportParameters);

        ArgumentCaptor<Long> errorCaptor = ArgumentCaptor.forClass(Long.class);
        verify(connection).immediateCloseWithError(errorCaptor.capture(), any(), any());
        assertThat(errorCaptor.getValue()).isEqualTo(TRANSPORT_PARAMETER_ERROR.value);
    }
    //endregion

    //region transport parameters
    @Test
    void invalidStatelessResetTransportParameterShouldThrow() {
        // Given
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setStatelessResetToken(new byte[13]);

        // When
        assertThatThrownBy(() -> connection.setPeerTransportParameters(transportParameters))
                // Then
                .isInstanceOf(TransportError.class);
    }

    @Test
    void invalidPreferredAddressTransportParameterShouldThrow() throws Exception {
        // Given
        TransportParameters transportParameters = new TransportParameters();
        TransportParameters.PreferredAddress preferredAddress = new TransportParameters.PreferredAddress();
        preferredAddress.setIp4(Inet4Address.getByAddress(new byte[] { 0x01, 0x02, 0x03, 0x04 }));
        preferredAddress.setConnectionId(ByteBuffer.allocate(0), 0);
        transportParameters.setPreferredAddress(preferredAddress);

        // When
        assertThatThrownBy(() -> connection.setPeerTransportParameters(transportParameters))
                // Then
                .isInstanceOf(TransportError.class);
    }

    @Test
    void invalidMaxUdpPayloadSizeShouldThrow() {
        // Given
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setMaxUdpPayloadSize(1111);

        // When
        assertThatThrownBy(() -> connection.setPeerTransportParameters(transportParameters))
                // Then
                .isInstanceOf(TransportError.class);
    }

    @Test
    void invalidMaxAckDelayShouldThrow() {
        // Given
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setMaxAckDelay(16_789);

        // When
        assertThatThrownBy(() -> connection.setPeerTransportParameters(transportParameters))
                // Then
                .isInstanceOf(TransportError.class);
    }

    @Test
    void invalidAckDelayExponentShouldThrow() {
        // Given
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setAckDelayExponent(21);

        // When
        assertThatThrownBy(() -> connection.setPeerTransportParameters(transportParameters))
                // Then
                .isInstanceOf(TransportError.class);
    }

    @Test
    void invalidActiveConnectionIdLimitShouldThrow() {
        // Given
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setActiveConnectionIdLimit(1);

        // When
        assertThatThrownBy(() -> connection.setPeerTransportParameters(transportParameters))
                // Then
                .isInstanceOf(TransportError.class);
    }
    //endregion

    //region stream
    @Test
    void testCreateStream() throws Exception {
        simulateSuccessfulConnect();
        TransportParameters parameters = new TransportParameters(10, 10, 10, 10);
        parameters.setInitialSourceConnectionId(connection.getDestinationConnectionId());
        parameters.setOriginalDestinationConnectionId(connection.getDestinationConnectionId());
        connection.setPeerTransportParameters(parameters);

        QuicStream stream = connection.createStream(true);
        int firstStreamId = stream.getStreamId();
        int streamIdLowBits = firstStreamId & 0x03;

        assertThat(streamIdLowBits).isEqualTo(0x00);

        QuicStream stream2 = connection.createStream(true);
        assertThat(stream2.getStreamId()).isEqualTo(firstStreamId + 4);
    }

    @Test
    void beforeHandshakeIsCompletedCreatingStreamShouldThrow() throws Exception {
        //  Given
        simulateHandshaking();

        assertThatThrownBy(() ->
                // When
                connection.createStream(true))
                // Then
                .isInstanceOf(IOException.class);
    }

    @Test
    void whenClosedCreatingStreamShouldThrow() throws Exception {
        // Given
        simulateSuccessfulConnect();
        connection.close();

        assertThatThrownBy(() ->
                // When
                connection.createStream(true))
                // Then
                .isInstanceOf(IOException.class);
    }
    //endregion

    //region flow control
    @Test
    void receivingTransportParametersInitializesFlowController() throws Exception {
        simulateSuccessfulConnect();
        TransportParameters parameters = new TransportParameters(30, 9000, 1, 1);
        parameters.setInitialSourceConnectionId(connection.getDestinationConnectionId());
        parameters.setOriginalDestinationConnectionId(connection.getDestinationConnectionId());
        connection.setPeerTransportParameters(parameters);
        QuicStream stream = connection.createStream(true);
        assertThat(connection.getFlowController().increaseFlowControlLimit(stream, 9999)).isEqualTo(9000);
    }

    @Test
    void receivingMaxStreamDataFrameIncreasesFlowControlLimit() throws Exception {
        simulateSuccessfulConnect();
        TransportParameters parameters = new TransportParameters(10, 0, 3, 3);
        parameters.setInitialSourceConnectionId(connection.getDestinationConnectionId());
        parameters.setOriginalDestinationConnectionId(connection.getDestinationConnectionId());
        parameters.setInitialMaxData(100_000);
        parameters.setInitialMaxStreamDataBidiRemote(9000);
        connection.setPeerTransportParameters(parameters);

        QuicStream stream = connection.createStream(true);
        assertThat(connection.getFlowController().increaseFlowControlLimit(stream, 9999)).isEqualTo(9000);
        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new MaxStreamDataFrame(stream.getStreamId(), 10_000)), mock(PacketMetaData.class));

        assertThat(connection.getFlowController().increaseFlowControlLimit(stream, 99999)).isEqualTo(10_000);
    }

    @Test
    void receivingMaxDataFrameIncreasesFlowControlLimit() throws Exception {
        simulateSuccessfulConnect();
        TransportParameters parameters = new TransportParameters(10, 0, 3, 3);
        parameters.setInitialSourceConnectionId(connection.getDestinationConnectionId());
        parameters.setOriginalDestinationConnectionId(connection.getDestinationConnectionId());
        parameters.setInitialMaxData(1_000);
        parameters.setInitialMaxStreamDataBidiRemote(9000);
        connection.setPeerTransportParameters(parameters);

        QuicStream stream = connection.createStream(true);
        assertThat(connection.getFlowController().increaseFlowControlLimit(stream, 9999)).isEqualTo(1000);
        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new MaxDataFrame(4_000)), mock(PacketMetaData.class));

        assertThat(connection.getFlowController().increaseFlowControlLimit(stream, 99999)).isEqualTo(4_000);
    }
    //endregion

    //region connection close
    @Test
    void receivingConnectionCloseWhileConnectedResultsInReplyWithConnectionClose() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        FieldSetter.setField(connection, connection.getClass().getSuperclass().getDeclaredField("connectionState"), QuicClientConnectionImpl.Status.Connected);

        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new ConnectionCloseFrame(Version.getDefault())), mock(PacketMetaData.class));

        verify(sender).send(argThat(frame -> frame instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void receivingConnectionCloseWhileConnectedResultsInReplyWithConnectionCloseOnce() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        FieldSetter.setField(connection, connection.getClass().getSuperclass().getDeclaredField("connectionState"), QuicClientConnectionImpl.Status.Connected);

        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new ConnectionCloseFrame(Version.getDefault())), mock(PacketMetaData.class));
        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new ConnectionCloseFrame(Version.getDefault())), mock(PacketMetaData.class));
        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new ConnectionCloseFrame(Version.getDefault())), mock(PacketMetaData.class));

        verify(sender, times(1)).send(argThat(frame -> frame instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void closingConnectedConnectionTriggersConnectionClose() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        FieldSetter.setField(connection, connection.getClass().getSuperclass().getDeclaredField("connectionState"), QuicClientConnectionImpl.Status.Connected);

        connection.close();

        verify(sender).send(argThat(frame -> frame instanceof ConnectionCloseFrame), any(EncryptionLevel.class));
    }
    //endregion

    //region connection id
    @Test
    void receivingRetireConnectionIdLeadsToNewSourceConnectionId() throws Exception {
        // Given
        simulateSuccessfulConnect();
        setTransportParametersWithActiveConnectionIdLimit(3);
        connection.newConnectionIds(1, 0);
        assertThat(connection.getSourceConnectionIds()).hasSize(2);

        RetireConnectionIdFrame retireFrame = new RetireConnectionIdFrame(Version.getDefault(), 0);
        connection.processFrames(new ShortHeaderPacket(Version.getDefault(), connection.getSourceConnectionId(), retireFrame), mock(PacketMetaData.class));

        assertThat(connection.getSourceConnectionIds()).hasSize(2);
        verify(sender).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void receivingPacketWitYetUnusedConnectionIdLeadsToNewSourceConnectionId() throws Exception {
        // Given
        simulateSuccessfulConnect();
        setTransportParametersWithActiveConnectionIdLimit(7);

        // When
        byte[] newUnusedConnectionId = connection.newConnectionIds(1, 0)[0];
        assertThat(newUnusedConnectionId).isNotEqualTo(connection.getSourceConnectionId());
        clearInvocations(sender);

        connection.process(new ShortHeaderPacket(Version.getDefault(), newUnusedConnectionId, new Padding(20)),  mock(PacketMetaData.class));

        // Then
        assertThat(connection.getSourceConnectionIds().get(0).getConnectionIdStatus()).isEqualTo(ConnectionIdStatus.USED);
        verify(sender, times(1)).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void receivingPacketWitYetUnusedConnectionIdDoesNotLeadToNewSourceConnectionIdWhenActiveCidLimitReached() throws Exception {
        // Given
        simulateSuccessfulConnect();
        setTransportParametersWithActiveConnectionIdLimit(2);

        byte[][] newConnectionIds = connection.newConnectionIds(1, 0);
        byte[] nextConnectionId = newConnectionIds[0];
        assertThat(nextConnectionId).isNotEqualTo(connection.getSourceConnectionId());

        clearInvocations(sender);
        // When
        connection.process(new ShortHeaderPacket(Version.getDefault(), nextConnectionId, new Padding(20)),  mock(PacketMetaData.class));

        // Then
        verify(sender, never()).send(any(QuicFrame.class), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void receivingPacketWitPrevouslyUsedConnectionIdDoesNotLeadToNewSourceConnectionId() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);

        TransportParameters params = new TransportParameters();
        params.setActiveConnectionIdLimit(8);
        connection.setPeerTransportParameters(params);

        byte[] firstConnectionId = connection.getSourceConnectionId();
        Map<Integer, ConnectionIdInfo> sourceConnectionIds = connection.getSourceConnectionIds();
        byte[][] newConnectionIds = connection.newConnectionIds(1, 0);
        byte[] nextConnectionId = newConnectionIds[0];
        assertThat(nextConnectionId).isNotEqualTo(connection.getSourceConnectionId());
        connection.process(new ShortHeaderPacket(Version.getDefault(), nextConnectionId, new Padding(20)), mock(PacketMetaData.class));

        clearInvocations(sender);
        connection.process(new ShortHeaderPacket(Version.getDefault(), firstConnectionId, new Padding(20)),  mock(PacketMetaData.class));

        verify(sender, never()).send(any(QuicFrame.class), any(EncryptionLevel.class), any(Consumer.class));
    }

    /*
    // TODO: this test must move to sender (?), as connection does not create packets anymore
    @Test
    void afterProcessingNewConnectionIdFrameWithRetireTheNewConnectionIdIsUsed() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);

        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionState"), QuicConnectionImpl.Status.Connected);

        NewConnectionIdFrame newConnectionIdFrame = new NewConnectionIdFrame(Version.getDefault(), 1, 1, new byte[]{ 0x0c, 0x0f, 0x0d, 0x0e });
        connection.process(new ShortHeaderPacket(Version.getDefault(), connection.getSourceConnectionId(), newConnectionIdFrame), Instant.now());

        ArgumentCaptor<QuicPacket> captor = ArgumentCaptor.forClass(QuicPacket.class);
        verify(sender, times(1)).send(captor.capture(), anyString(), any(Consumer.class));
        QuicPacket packetSent = captor.getValue();

        assertThat(((ShortHeaderPacket) packetSent).getDestinationConnectionId()).isEqualTo(new byte[]{ 0x0c, 0x0f, 0x0d, 0x0e });
        assertThat(packetSent.getFrames()).contains(new RetireConnectionIdFrame(Version.getDefault(), 0));
    }
*/
    @Test
    void retireConnectionIdFrameShouldBeRetransmittedWhenLost() throws Exception {
        // Given
        FieldSetter.setField(connection, connection.getClass().getSuperclass().getDeclaredField("connectionState"), QuicClientConnectionImpl.Status.Connected);
        connection.process(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[]{ 0x0c, 0x0f, 0x0d, 0x0e }), null, mock(PacketMetaData.class));

        // When
        connection.retireDestinationConnectionId(0);

        ArgumentCaptor<QuicFrame> frameCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        ArgumentCaptor<Consumer> captor = ArgumentCaptor.forClass(Consumer.class);
        verify(sender, times(1)).send(frameCaptor.capture(), any(EncryptionLevel.class), captor.capture());

        clearInvocations(sender);

        Consumer lostPacketCallback = captor.getValue();
        lostPacketCallback.accept(frameCaptor.getValue());

        // Then
        ArgumentCaptor<QuicFrame> secondFrameCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(sender, times(1)).send(secondFrameCaptor.capture(), any(EncryptionLevel.class), any(Consumer.class));
        QuicFrame retransmitPacket = secondFrameCaptor.getValue();
        assertThat(retransmitPacket).isEqualTo(new RetireConnectionIdFrame(Version.getDefault(), 0));
    }

    @Test
    void receivingReorderedNewConnectionIdWithSequenceNumberThatIsAlreadyRetiredShouldImmediatelySendRetire() throws Exception {
        // Given
        FieldSetter.setField(connection, connection.getClass().getSuperclass().getDeclaredField("connectionState"), QuicClientConnectionImpl.Status.Connected);
        connection.process(new NewConnectionIdFrame(Version.getDefault(), 4, 3, new byte[]{ 0x04, 0x04, 0x04, 0x04 }), null, mock(PacketMetaData.class));
        clearInvocations(sender);

        // When
        connection.process(new NewConnectionIdFrame(Version.getDefault(), 2, 0, new byte[]{ 0x02, 0x02, 0x02, 0x02 }), null, mock(PacketMetaData.class));

        // Then
        verify(sender).send(argThat(frame -> frame.equals(new RetireConnectionIdFrame(Version.getDefault(), 2))), any(EncryptionLevel.class), any(Consumer.class));
    }
    //endregion

    // region version negotiation
    @Test
    void processingVersionNegotationWithClientVersionShouldBeIgnored() {
        VersionNegotiationPacket vnWithClientVersion = mock(VersionNegotiationPacket.class);
        when(vnWithClientVersion.getServerSupportedVersions()).thenReturn(List.of(Version.getDefault()));

        try {
            connection.process(vnWithClientVersion, null);
        }
        catch (Throwable exception) {
            exception.printStackTrace();
            fail();
        }
    }

    @Test
    void versionNegotationAfterClientHasReceivedOthePacketShouldBeIgnored() {
        VersionNegotiationPacket vn = new VersionNegotiationPacket();
        connection.process(new InitialPacket(Version.getDefault(), new byte[0], new byte[0], new byte[0], new PingFrame()), mock(PacketMetaData.class));

        try {
            connection.process(vn, null);
        }
        catch (Throwable exception) {
            fail();
        }
    }
    //endregion
    
    //region discard keys
    @Test
    void whenHandshakePacketIsSendInitialKeysShouldBeDiscarded() throws Exception {
        // Given
        ConnectionSecrets connectionSecrets = mock(ConnectionSecrets.class);
        FieldSetter.setField(connection, QuicConnectionImpl.class.getDeclaredField("connectionSecrets"), connectionSecrets);
        simulateSuccessfulConnect();

        // When
        connection.handshakeSecretsKnown();
        // And
        connection.runPostProcessingActions();

        // Then
        verify(connectionSecrets).discardKeys(argThat(level -> level == EncryptionLevel.Initial));
    }

    @Test
    void whenHandshakeIsConfirmedHandshakeKeysShouldBeDiscarded() throws Exception {
        // Given
        ConnectionSecrets connectionSecrets = mock(ConnectionSecrets.class);
        FieldSetter.setField(connection, QuicConnectionImpl.class.getDeclaredField("connectionSecrets"), connectionSecrets);

        // When
        connection.process(new HandshakeDoneFrame(Version.getDefault()), mock(QuicPacket.class), mock(PacketMetaData.class));

        // Then
        verify(connectionSecrets).discardKeys(argThat(level -> level == EncryptionLevel.Handshake));
    }
    //endregion

    //region change settings
    @Test
    void settingUniBufferSizeBeforeConnectShouldWork() throws Exception {
        // When
        connection.setDefaultUnidirectionalStreamReceiveBufferSize(1024);
        simulateSuccessfulConnect();

        // Then
        assertThat(connection.getStreamManager().getMaxUnidirectionalStreamBufferSize()).isEqualTo(1024);
    }

    @Test
    void settingUniBufferSizeAterConnectShouldWork() throws Exception {
        // When
        simulateSuccessfulConnect();
        connection.setDefaultUnidirectionalStreamReceiveBufferSize(1024);

        // Then
        assertThat(connection.getStreamManager().getMaxUnidirectionalStreamBufferSize()).isEqualTo(1024);
    }

    @Test
    void settingUniBufferSizeToValueLargerThanConnectionBufferSizeShouldThrow() throws Exception {
        assertThatThrownBy(() ->
                // When
                connection.setDefaultUnidirectionalStreamReceiveBufferSize(3_500_000))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void settingBidiBufferSizeBeforeConnectShouldWork() throws Exception {
        // When
        connection.setDefaultBidirectionalStreamReceiveBufferSize(1024);
        simulateSuccessfulConnect();

        // Then
        assertThat(connection.getStreamManager().getMaxBidirectionalStreamBufferSize()).isEqualTo(1024);
    }

    @Test
    void settingBidiBufferSizeAfterConnectShouldWork() throws Exception {
        // When
        simulateSuccessfulConnect();
        connection.setDefaultBidirectionalStreamReceiveBufferSize(1024);

        // Then
        assertThat(connection.getStreamManager().getMaxBidirectionalStreamBufferSize()).isEqualTo(1024);
    }

    @Test
    void settingBidiBufferSizeToValueLargerThanConnectionBufferSizeShouldThrow() throws Exception {
        // When
        simulateSuccessfulConnect();

        // Then
        assertThatThrownBy(() -> connection.setDefaultBidirectionalStreamReceiveBufferSize(3_500_000))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void whenDatagramExtensionIsEnabledTransportParameterShouldBeSent() throws Exception {
        // Given
        connection.enableDatagramExtension();

        // When
        TransportParameters transportParameters = connection.initTransportParameters();

        // Then
        assertThat(transportParameters.getMaxDatagramFrameSize()).isGreaterThan(0);
    }
    //endregion

    //region statelessreset
    @Test
    void whenStatelessResetIsReceivedConnectionShouldBeClosed() throws Exception {
        // Given
        ConnectionIdManager connectionIdManager = mock(ConnectionIdManager.class);
        when(connectionIdManager.isStatelessResetToken(any())).thenReturn(true);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionIdManager"), connectionIdManager);

        // When
        ByteBuffer data = ByteBuffer.allocate(60);
        connection.handleUnprotectPacketFailure(data, null);

        // Then
        assertThat(connection.connectionState).isEqualTo(QuicConnectionImpl.Status.Draining);
    }

    @Test
    void whenStatelessResetIsReceivedAllStreamsAreAborted() throws Exception {
        // Given
        ConnectionIdManager connectionIdManager = mock(ConnectionIdManager.class);
        when(connectionIdManager.isStatelessResetToken(any())).thenReturn(true);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionIdManager"), connectionIdManager);

        StreamManager streamManager = mock(StreamManager.class);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("streamManager"), streamManager);

        // When
        ByteBuffer data = ByteBuffer.allocate(60);
        connection.handleUnprotectPacketFailure(data, null);

        // Then
        verify(streamManager).abortAll();
    }

    @Test
    void whenStatelessResetIsReceivedConnectionListenerIsCalled() throws Exception {
        // Given
        ConnectionIdManager connectionIdManager = mock(ConnectionIdManager.class);
        when(connectionIdManager.isStatelessResetToken(any())).thenReturn(true);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionIdManager"), connectionIdManager);

        ConnectionListener listener = mock(ConnectionListener.class);
        connection.setConnectionListener(listener);

        // When
        ByteBuffer data = ByteBuffer.allocate(60);
        connection.handleUnprotectPacketFailure(data, null);
        testScheduledExecutor.check();

        // Then
        ArgumentCaptor<ConnectionTerminatedEvent> eventCaptor = ArgumentCaptor.forClass(ConnectionTerminatedEvent.class);
        verify(listener).disconnected(eventCaptor.capture());
        ConnectionTerminatedEvent connectionTerminatedEvent = eventCaptor.getValue();
        assertThat(connectionTerminatedEvent.closeReason()).isEqualTo(ConnectionTerminatedEvent.CloseReason.StatelessReset);
        assertThat(connectionTerminatedEvent.closedByPeer()).isTrue();
        assertThat(connectionTerminatedEvent.hasApplicationError()).isFalse();
    }
    //endregion

    //region misc
    @Test
    void receivingNewTokenFrameWithEmptyTokenShouldLeadToConnectionError() {
        // Given
        NewTokenFrame newTokenFrame = new NewTokenFrame(new byte[0]);

        // When
        connection.process(newTokenFrame, mock(QuicPacket.class), mock(PacketMetaData.class));

        // Then
        verify(sender).send(argThat(frame -> frame instanceof ConnectionCloseFrame &&
                        ((ConnectionCloseFrame) frame).getErrorCode() == FRAME_ENCODING_ERROR.value),
                any(EncryptionLevel.class));
    }
    //endregion

    //region helper methods
    private void setFixedOriginalDestinationConnectionId(byte[] originalConnectionId) throws Exception {
        var connectionIdManager = new FieldReader(connection, connection.getClass().getDeclaredField("connectionIdManager")).read();
        FieldSetter.setField(connectionIdManager,
                connectionIdManager.getClass().getDeclaredField("originalDestinationConnectionId"),
                originalConnectionId);
    }

    private RetryPacket createRetryPacket(byte[] originalDestinationConnectionId, String integrityTagValue) throws Exception {
        byte[] sourceConnectionId = { 0x0b, 0x0b, 0x0b, 0x0b };
        byte[] destinationConnectionId = { 0x0f, 0x0f, 0x0f, 0x0f };
        byte[] retryToken = { 0x01, 0x02, 0x03 };
        RetryPacket retryPacket = new RetryPacket(Version.getDefault(), sourceConnectionId, destinationConnectionId, originalDestinationConnectionId, retryToken);
        FieldSetter.setField(retryPacket, RetryPacket.class.getDeclaredField("retryIntegrityTag"), ByteUtils.hexToBytes(integrityTagValue));
        return retryPacket;
    }

    private RetryPacket simulateConnectionReceivingRetryPacket() throws Exception {
        simulateSuccessfulConnect();

        originalDestinationId = new byte[]{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
        // By using a fixed value for the original destination connection, the integrity tag will also have a fixed value, which simplifies the test
        setFixedOriginalDestinationConnectionId(originalDestinationId);

        // Simulate a RetryPacket is received
        RetryPacket retryPacket = createRetryPacket(connection.getDestinationConnectionId(), "9442e0ac29f6d650adc5e4b4a3cd12cc");
        connection.process(retryPacket, null);
        return retryPacket;
    }

    private void simulateSuccessfulConnect() throws Exception {
        simulateConnect(QuicConnectionImpl.Status.Connected);
    }

    private void simulateHandshaking() throws Exception {
        simulateConnect(QuicConnectionImpl.Status.Handshaking);
    }

    private void simulateConnect(QuicConnectionImpl.Status finalStatus) throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        when(sender.getCongestionController()).thenReturn(new FixedWindowCongestionController(logger));

        tlsClientEngine = mock(TlsClientEngine.class);
        FieldSetter.setField(connection, "tlsEngine", tlsClientEngine);
        FieldSetter.setField(connection, "originalClientHello", createClientHello());

        Object connectionProperties = new FieldReader(connection, connection.getClass().getDeclaredField("connectionProperties")).read();
        connection.getStreamManager().initialize((ConnectionConfig) connectionProperties);

        TransportParameters transportParams = connection.initTransportParameters();
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("transportParams"), transportParams);

        FieldSetter.setField(connection, QuicConnectionImpl.class.getDeclaredField("connectionState"), finalStatus);
    }

    private void setTransportParametersWithActiveConnectionIdLimit(int connectionIdLimit) throws Exception {
        TransportParameters params = new TransportParameters();
        params.setInitialSourceConnectionId(connection.getDestinationConnectionId());
        params.setOriginalDestinationConnectionId(connection.getDestinationConnectionId());
        params.setActiveConnectionIdLimit(connectionIdLimit);
        connection.setPeerTransportParameters(params);
    }

    private ClientHello createClientHello() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec(secp256r1.toString()));
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        return new ClientHello("example.com", publicKey);
    }
    //endregion
}
