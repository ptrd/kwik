/*
 * Copyright © 2019, 2020 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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
package net.luminis.quic;

import net.luminis.quic.cc.FixedWindowCongestionController;
import net.luminis.quic.cid.ConnectionIdInfo;
import net.luminis.quic.cid.ConnectionIdStatus;
import net.luminis.quic.cid.DestinationConnectionIdRegistry;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.packet.*;
import net.luminis.quic.send.Sender;
import net.luminis.quic.send.SenderImpl;
import net.luminis.quic.stream.QuicStream;
import net.luminis.tls.ByteUtils;
import net.luminis.tls.TlsState;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.FieldReader;
import org.mockito.internal.util.reflection.FieldSetter;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class QuicConnectionImplTest {

    private static Logger logger;
    private final byte[] destinationConnectionId = { 0x00, 0x01, 0x02, 0x03 };

    private QuicConnectionImpl connection;
    private byte[] originalDestinationId;
    private SenderImpl sender;

    @BeforeAll
    static void initLogger() {
        logger = new SysOutLogger();
        // logger.logDebug(true);
    }

    @BeforeEach
    void initConnectionUnderTest() throws Exception {
        connection = QuicConnectionImpl.newBuilder().uri(new URI("//localhost:443")).logger(logger).build();
        sender = Mockito.mock(SenderImpl.class);
    }

    @Test
    void testRetryPacketInitiatesInitialPacketWithToken() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        InOrder recorder = inOrder(sender);
        when(sender.getCongestionController()).thenReturn(new FixedWindowCongestionController(logger));

        byte[] originalConnectionId = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
        // By using a fixed value for the original destination connection, the integrity tag will also have a fixed value, which simplifies the test
        setFixedOriginalDestinationConnectionId(originalConnectionId);

        new Thread(() -> {
            try {
                connection.connect(3);
            } catch (IOException e) {}
        }).start();

        Thread.sleep(1000);  // Give connection a chance to send packet.

        // First InitialPacket should not contain a token.
        recorder.verify(sender).sendInitial(any(QuicFrame.class), argThat(token -> token == null));

        // Simulate a RetryPacket is received
        RetryPacket retryPacket = createRetryPacket(originalConnectionId, "2b57643b17ca7ce7c345771c37e1c6ed");
        connection.process(retryPacket, null);

        // A second InitialPacket should be send with token
        recorder.verify(sender).sendInitial(any(QuicFrame.class),
                argThat(token -> token != null && Arrays.equals(token, new byte[] { 0x01, 0x02, 0x03 })));
    }

    private void setFixedOriginalDestinationConnectionId(byte[] originalConnectionId) throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("destConnectionIds"),
                new DestinationConnectionIdRegistry(originalConnectionId, mock(Logger.class)));
    }

    @Test
    void testSecondRetryPacketShouldBeIgnored() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        when(sender.getCongestionController()).thenReturn(new FixedWindowCongestionController(logger));

        byte[] originalConnectionId = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
        // By using a fixed value for the original destination connection, the integrity tag will also have a fixed value, which simplifies the test
        setFixedOriginalDestinationConnectionId(originalConnectionId);

        new Thread(() -> {
            try {
                connection.connect(3);
            } catch (IOException e) {
            }
        }).start();

        Thread.sleep(1000);  // Give connection a chance to send packet(s).

        // Simulate a first RetryPacket is received
        RetryPacket retryPacket = createRetryPacket(connection.getDestinationConnectionId(), "5e5f918434a24d4b601745b4f0db7908");
        connection.process(retryPacket, null);

        clearInvocations(sender);

        // Simulate a second RetryPacket is received
        RetryPacket secondRetryPacket = createRetryPacket(connection.getDestinationConnectionId(), "00f4bbc72790b7c7947f86ec9fb0a68d");
        connection.process(secondRetryPacket, null);

        verify(sender, never()).send(any(QuicFrame.class), any(EncryptionLevel.class), any(Consumer.class));
    }

    private RetryPacket createRetryPacket(byte[] originalDestinationConnectionId, String integrityTagValue) throws Exception {
        byte[] sourceConnectionId = { 0x0b, 0x0b, 0x0b, 0x0b };
        byte[] destinationConnectionId = { 0x0f, 0x0f, 0x0f, 0x0f };
        byte[] retryToken = { 0x01, 0x02, 0x03 };
        RetryPacket retryPacket = new RetryPacket(Version.getDefault(), sourceConnectionId, destinationConnectionId, originalDestinationConnectionId, retryToken);
        FieldSetter.setField(retryPacket, RetryPacket.class.getDeclaredField("retryIntegrityTag"), ByteUtils.hexToBytes(integrityTagValue));
        return retryPacket;
    }

    @Test
    void testRetryPacketWithIncorrectOriginalDestinationIdShouldBeDiscarded() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        when(sender.getCongestionController()).thenReturn(new FixedWindowCongestionController(logger));

        new Thread(() -> {
            try {
                connection.connect(3);
            } catch (IOException e) {
            }
        }).start();

        Thread.sleep(1000);  // Give connection a chance to send packet(s).

        clearInvocations(sender);

        // Simulate a RetryPacket with arbitrary original destination id is received
        RetryPacket retryPacket = createRetryPacket(new byte[] { 0x03, 0x0a, 0x0d, 0x09 }, "00112233445566778899aabbccddeeff");
        connection.process(retryPacket, null);

        verify(sender, never()).send(any(QuicFrame.class), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void testAfterRetryPacketTransportParametersWithoutOriginalDestinationIdLeadsToConnectionError() throws Exception {
        simulateConnectionReceivingRetryPacket();

        // Simulate a TransportParametersExtension is received that does not contain the right original destination id
        connection.setPeerTransportParameters(new TransportParameters());

        verify(connection).signalConnectionError(argThat(error -> error == QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR));
    }

    @Test
    void testAfterRetryPacketTransportParametersWithIncorrectOriginalDestinationIdLeadsToConnectionError() throws Exception {
        RetryPacket retryPacket = simulateConnectionReceivingRetryPacket();

        // Simulate a TransportParametersExtension is received that...
        TransportParameters transportParameters = new TransportParameters();
        // - has the server's source cid (because the test stops after "sending" the retry-packet, this is not the "final" server source cid, but the one used in the retry packet)
        transportParameters.setInitialSourceConnectionId(retryPacket.getSourceConnectionId());
        // - does contain the original destination id
        transportParameters.setOriginalDestinationConnectionId(originalDestinationId);
        // -  does contain an original destination id (but incorrect)
        transportParameters.setRetrySourceConnectionId(new byte[] { 0x0d, 0x0d, 0x0d, 0x0d });
        connection.setPeerTransportParameters(transportParameters);

        verify(connection).signalConnectionError(argThat(error -> error == QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR));
    }

    @Test
    void testAfterRetryPacketTransportParametersWithCorrectRetrySourceConnectionId() throws Exception {
        RetryPacket retryPacket = simulateConnectionReceivingRetryPacket();

        // Simulate a TransportParametersExtension is received that...
        TransportParameters transportParameters = new TransportParameters();
        // - has the server's source cid (because the test stops after "sending" the retry-packet, this is not the "final" server source cid, but the one used in the retry packet)
        transportParameters.setInitialSourceConnectionId(retryPacket.getSourceConnectionId());
        // - does contain the original destination id
        transportParameters.setOriginalDestinationConnectionId(originalDestinationId);
        // - sets the retry cid to the source cid of the retry packet
        transportParameters.setRetrySourceConnectionId(retryPacket.getSourceConnectionId());
        connection.setPeerTransportParameters(transportParameters);

        verify(connection, never()).signalConnectionError(any());
    }

    @Test
    void testWithNormalConnectionTransportParametersShouldNotContainRetrySourceId() throws Exception {
        byte[] originalSourceConnectionId = new byte[] { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
        setFixedOriginalDestinationConnectionId(originalSourceConnectionId);
        simulateNormalConnection();

        // Simulate a TransportParametersExtension is received that does not contain a retry source id
        TransportParameters transportParameters = new TransportParameters();
        // But it must contain
        transportParameters.setInitialSourceConnectionId(connection.getDestinationConnectionId());
        transportParameters.setOriginalDestinationConnectionId(originalSourceConnectionId);
        connection.setPeerTransportParameters(transportParameters);

        verify(connection, never()).signalConnectionError(any());
    }

    @Test
    void testOnNormalConnectionTransportParametersWithOriginalDestinationIdLeadsToConnectionError() throws Exception {
        simulateNormalConnection();

        // Simulate a TransportParametersExtension is received that does contain an original destination id
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setRetrySourceConnectionId(new byte[] { 0x0d, 0x0d, 0x0d, 0x0d });
        connection.setPeerTransportParameters(transportParameters);

        verify(connection).signalConnectionError(argThat(error -> error == QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR));
    }

    private RetryPacket simulateConnectionReceivingRetryPacket() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        when(sender.getCongestionController()).thenReturn(new FixedWindowCongestionController(logger));

        byte[] originalConnectionId = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
        // By using a fixed value for the original destination connection, the integrity tag will also have a fixed value, which simplifies the test
        setFixedOriginalDestinationConnectionId(originalConnectionId);

        connection = Mockito.spy(connection);

        new Thread(() -> {
            try {
                connection.connect(3);
            } catch (IOException e) {
            }
        }).start();
        Thread.sleep(100);  // Give connection a chance to send packet(s).

        // Store original destination id
        originalDestinationId = connection.getDestinationConnectionId();

        // Simulate a RetryPacket is received
        RetryPacket retryPacket = createRetryPacket(connection.getDestinationConnectionId(), "2b57643b17ca7ce7c345771c37e1c6ed");
        connection.process(retryPacket, null);
        return retryPacket;
    }

    private void simulateNormalConnection() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        when(sender.getCongestionController()).thenReturn(new FixedWindowCongestionController(logger));
        connection = Mockito.spy(connection);

        new Thread(() -> {
            try {
                connection.connect(3);
            } catch (IOException e) {
            }
        }).start();
        Thread.sleep(100);  // Give connection a chance to send packet(s).
    }

    @Test
    void testCreateStream() throws Exception {
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
    void testConnectionFlowControl() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        long flowControlIncrement = (long) new FieldReader(connection, connection.getClass().getDeclaredField("flowControlIncrement")).read();

        connection.updateConnectionFlowControl(10);
        verify(sender, never()).send(any(QuicFrame.class), any(EncryptionLevel.class), any(Consumer.class));  // No initial update, value is advertised in transport parameters.

        connection.updateConnectionFlowControl((int) flowControlIncrement);
        verify(sender, times(1)).send(any(QuicFrame.class), any(EncryptionLevel.class), any(Consumer.class));

        connection.updateConnectionFlowControl((int) (flowControlIncrement * 0.8));
        verify(sender, times(1)).send(any(QuicFrame.class), any(EncryptionLevel.class), any(Consumer.class));

        connection.updateConnectionFlowControl((int) (flowControlIncrement * 0.21));
        verify(sender, times(2)).send(any(QuicFrame.class), any(EncryptionLevel.class) , any(Consumer.class));
    }

    @Test
    void testMinimumQuicVersionIs23() {
        assertThatThrownBy(
                () -> QuicConnectionImpl.newBuilder()
                        .version(Version.IETF_draft_19)
                        .uri(new URI("//localhost:443"))
                        .logger(logger).build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testQuicVersion23IsSupported() throws Exception {
        assertThat(QuicConnectionImpl.newBuilder()
                .version(Version.IETF_draft_23)
                .uri(new URI("//localhost:443"))
                .logger(logger).build())
                .isNotNull();
    }

    @Test
    void parsingValidVersionNegotiationPacketShouldSucceed() throws Exception {
        QuicPacket packet = connection.parsePacket(ByteBuffer.wrap(ByteUtils.hexToBytes("ff00000000040a0b0c0d040f0e0d0cff000018")));
        assertThat(packet).isInstanceOf(VersionNegotiationPacket.class);
    }

    @Test
    void receivingTransportParametersInitializesFlowController() {
        TransportParameters parameters = new TransportParameters(30, 9000, 1, 1);
        parameters.setInitialSourceConnectionId(connection.getDestinationConnectionId());
        parameters.setOriginalDestinationConnectionId(connection.getDestinationConnectionId());
        connection.setPeerTransportParameters(parameters);
        QuicStream stream = connection.createStream(true);
        assertThat(connection.getFlowController().increaseFlowControlLimit(stream, 9999)).isEqualTo(9000);
    }

    @Test
    void receivingMaxStreamDataFrameIncreasesFlowControlLimit() {
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
                        new MaxStreamDataFrame(stream.getStreamId(), 10_000)), Instant.now());

        assertThat(connection.getFlowController().increaseFlowControlLimit(stream, 99999)).isEqualTo(10_000);
    }

    @Test
    void receivingMaxDataFrameIncreasesFlowControlLimit() {
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
                        new MaxDataFrame(4_000)), Instant.now());

        assertThat(connection.getFlowController().increaseFlowControlLimit(stream, 99999)).isEqualTo(4_000);
    }


    @Test
    void receivingConnectionCloseWhileConnectedResultsInReplyWithConnectionClose() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionState"), QuicConnectionImpl.Status.Connected);

        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new ConnectionCloseFrame(Version.getDefault())), Instant.now());

        verify(sender).send(argThat(frame -> frame instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void receivingConnectionCloseWhileConnectedResultsInReplyWithConnectionCloseOnce() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionState"), QuicConnectionImpl.Status.Connected);

        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new ConnectionCloseFrame(Version.getDefault())), Instant.now());
        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new ConnectionCloseFrame(Version.getDefault())), Instant.now());
        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new ConnectionCloseFrame(Version.getDefault())), Instant.now());

        verify(sender, times(1)).send(argThat(frame -> frame instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void closingConnectedConnectionTriggersConnectionClose() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionState"), QuicConnectionImpl.Status.Connected);

        connection.close();

        verify(sender).send(argThat(frame -> frame instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void receivingRetireConnectionIdLeadsToNewSourceConnectionId() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);

        assertThat(connection.getSourceConnectionIds()).hasSize(1);

        TransportParameters params = new TransportParameters();
        params.setInitialSourceConnectionId(connection.getDestinationConnectionId());
        params.setOriginalDestinationConnectionId(connection.getDestinationConnectionId());
        params.setActiveConnectionIdLimit(3);
        connection.setPeerTransportParameters(params);

        RetireConnectionIdFrame retireFrame = new RetireConnectionIdFrame(Version.getDefault(), 0);
        connection.processFrames(new ShortHeaderPacket(Version.getDefault(), connection.getSourceConnectionId(), retireFrame), Instant.now());

        assertThat(connection.getSourceConnectionIds()).hasSize(2);
        verify(sender).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(EncryptionLevel.class));
    }

    @Test
    void receivingPacketWitYetUnusedConnectionIdLeadsToNewSourceConnectionId() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);

        TransportParameters params = new TransportParameters();
        params.setInitialSourceConnectionId(connection.getDestinationConnectionId());
        params.setOriginalDestinationConnectionId(connection.getDestinationConnectionId());
        params.setActiveConnectionIdLimit(7);
        connection.setPeerTransportParameters(params);

        byte[][] newConnectionIds = connection.newConnectionIds(1, 0);
        byte[] nextConnectionId = newConnectionIds[0];
        assertThat(nextConnectionId).isNotEqualTo(connection.getSourceConnectionId());

        clearInvocations(sender);
        connection.process(new ShortHeaderPacket(Version.getDefault(), nextConnectionId, new Padding(20)), Instant.now());

        assertThat(connection.getSourceConnectionIds().get(0).getConnectionIdStatus()).isEqualTo(ConnectionIdStatus.USED);
        verify(sender, times(1)).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(EncryptionLevel.class));
    }

    @Test
    void receivingPacketWitYetUnusedConnectionIdDoesNotLeadToNewSourceConnectionIdWhenActiveCidLimitReached() throws Exception {
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);

        TransportParameters params = new TransportParameters();
        params.setActiveConnectionIdLimit(1);
        connection.setPeerTransportParameters(params);

        byte[][] newConnectionIds = connection.newConnectionIds(1, 0);
        byte[] nextConnectionId = newConnectionIds[0];
        assertThat(nextConnectionId).isNotEqualTo(connection.getSourceConnectionId());

        clearInvocations(sender);
        connection.process(new ShortHeaderPacket(Version.getDefault(), nextConnectionId, new Padding(20)), Instant.now());

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
        connection.process(new ShortHeaderPacket(Version.getDefault(), nextConnectionId, new Padding(20)), Instant.now());

        clearInvocations(sender);
        connection.process(new ShortHeaderPacket(Version.getDefault(), firstConnectionId, new Padding(20)), Instant.now());

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
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);

        // Given
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionState"), QuicConnectionImpl.Status.Connected);
        connection.registerNewDestinationConnectionId(new NewConnectionIdFrame(Version.getDefault(), 1, 0, new byte[]{ 0x0c, 0x0f, 0x0d, 0x0e }));

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
        assertThat(retransmitPacket.equals(new RetireConnectionIdFrame(Version.getDefault(), 0)));
    }

    @Test
    void receivingReorderedNewConnectionIdWithSequenceNumberThatIsAlreadyRetiredShouldImmediatelySendRetire() throws Exception {

        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);

        // Given
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionState"), QuicConnectionImpl.Status.Connected);
        connection.registerNewDestinationConnectionId(new NewConnectionIdFrame(Version.getDefault(), 4, 3, new byte[]{ 0x04, 0x04, 0x04, 0x04 }));
        clearInvocations(sender);

        // When
        connection.registerNewDestinationConnectionId(new NewConnectionIdFrame(Version.getDefault(), 2, 0, new byte[]{ 0x02, 0x02, 0x02, 0x02 }));

        // Then
        verify(sender).send(argThat(frame -> frame.equals(new RetireConnectionIdFrame(Version.getDefault(), 2))), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void processingVersionNegotationWithClientVersionShouldBeIgnored() {
        VersionNegotiationPacket vnWithClientVersion = mock(VersionNegotiationPacket.class);
        when(vnWithClientVersion.getServerSupportedVersions()).thenReturn(List.of(Version.getDefault()));

        try {
            connection.process(vnWithClientVersion, Instant.now());
        }
        catch (Throwable exception) {
            exception.printStackTrace();
            fail();
        }
    }

    @Test
    void versionNegotationAfterClientHasReceivedOthePacketShouldBeIgnored() {
        VersionNegotiationPacket vn = new VersionNegotiationPacket();
        connection.process(new InitialPacket(Version.getDefault(), new byte[0], new byte[0], new byte[0], new PingFrame()), Instant.now());

        try {
            connection.process(vn, Instant.now());
        }
        catch (Throwable exception) {
            fail();
        }
    }

    @Test
    void parseEmptyPacket() throws Exception {
        assertThatThrownBy(
                () -> connection.parsePacket(ByteBuffer.wrap(new byte[0]))
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseLongHeaderPacketWithInvalidHeader1() throws Exception {
        assertThatThrownBy(
                () -> connection.parsePacket(ByteBuffer.wrap(new byte[] { (byte) 0xc0, 0x00}))
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseLongHeaderPacketWithInvalidHeader2() throws Exception {
        assertThatThrownBy(
                () -> connection.parsePacket(ByteBuffer.wrap(new byte[] { (byte) 0xc0, 0x00, 0x00, 0x00 }))
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseShortHeaderPacketWithInvalidHeader() throws Exception {
        assertThatThrownBy(
                () -> connection.parsePacket(ByteBuffer.wrap(new byte[] { (byte) 0x40 }))
        ).isInstanceOf(InvalidPacketException.class);
    }

    void connectionShouldBeSilentlyClosedAfterIdleTimeout() throws Exception {

        // Given
        simulateNormalConnectionSetup(1);

        // When
        Thread.sleep(1000);

        // Then
        verify(connection, times(1)).silentlyCloseConnection(anyLong());
    }

    private void simulateNormalConnectionSetup(int idleTimeoutInSeconds) throws Exception {
        Sender sender = Mockito.mock(Sender.class);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionSecrets"), mock(ConnectionSecrets.class));
        connection = Mockito.spy(connection);

        new Thread(() -> {
            try {
                connection.connect(3 * idleTimeoutInSeconds * 1000);
            } catch (IOException e) {
                System.out.println("Exception in connect method: " + e);
            }
        }).start();

        connection.setPeerTransportParameters(new TransportParameters(idleTimeoutInSeconds, 1_000_000, 10, 10));
        connection.finishHandshake(new MockTlsState());
    }

    static class MockTlsState extends TlsState {
        @Override
        protected byte[] computeHandshakeFinishedHmac(boolean b) {
            return new byte[32];
        }
        @Override
        public boolean isServerFinished() {
            return true;
        }
        @Override
        public void computeApplicationSecrets() {
        }
    }
}
