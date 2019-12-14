/*
 * Copyright © 2019 Peter Doornbosch
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

import net.luminis.quic.frame.ConnectionCloseFrame;
import net.luminis.quic.frame.MaxDataFrame;
import net.luminis.quic.frame.MaxStreamDataFrame;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.packet.RetryPacket;
import net.luminis.quic.packet.ShortHeaderPacket;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.FieldReader;
import org.mockito.internal.util.reflection.FieldSetter;

import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.Arrays;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class QuicConnectionTest {

    private static Logger logger;
    private final byte[] destinationConnectionId = { 0x00, 0x01, 0x02, 0x03 };

    private QuicConnection connection;
    private byte[] originalDestinationId;

    @BeforeAll
    static void initLogger() {
        logger = new SysOutLogger();
        // logger.logDebug(true);
    }

    @BeforeEach
    void initConnectionUnderTest() throws SocketException, UnknownHostException {
        connection = new QuicConnection("localhost", 443, logger);
    }

    @Test
    void testRetryPacketInitiatesInitialPacketWithToken() throws Exception {
        Sender sender = Mockito.mock(Sender.class);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        InOrder recorder = inOrder(sender);
        when(sender.getCongestionController()).thenReturn(new FixedWindowCongestionController(logger));

        new Thread(() -> {
            try {
                connection.connect(3);
            } catch (IOException e) {}
        }).start();

        Thread.sleep(1000);  // Give connection a chance to send packet.

        // First InitialPacket should not contain a token.
        recorder.verify(sender).send(argThat((InitialPacket p) -> p.getToken() == null), anyString(), any(Consumer.class));

        // Simulate a RetryPacket is received
        RetryPacket retryPacket = createRetryPacket(connection.getDestinationConnectionId());
        connection.process(retryPacket, null);

        // A second InitialPacket should be send, with token and source connection id from retry packet
        recorder.verify(sender).send(argThat((InitialPacket p) ->
                p.getToken() != null
                && Arrays.equals(p.getToken(), new byte[] { 0x01, 0x02, 0x03 })
                && Arrays.equals(p.getDestinationConnectionId(), new byte[] { 0x0b, 0x0b, 0x0b, 0x0b })
        ), anyString(), any(Consumer.class));
    }

    @Test
    void testSecondRetryPacketShouldBeIgnored() throws Exception {
        Sender sender = Mockito.mock(Sender.class);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        when(sender.getCongestionController()).thenReturn(new FixedWindowCongestionController(logger));

        new Thread(() -> {
            try {
                connection.connect(3);
            } catch (IOException e) {
            }
        }).start();

        // Simulate a first RetryPacket is received
        RetryPacket retryPacket = createRetryPacket(connection.getDestinationConnectionId());
        connection.process(retryPacket, null);

        Thread.sleep(1000);  // Give connection a chance to send packet(s).

        clearInvocations(sender);

        // Simulate a second RetryPacket is received
        connection.process(retryPacket, null);

        verify(sender, never()).send(any(QuicPacket.class), anyString(), any(Consumer.class));
    }

    private RetryPacket createRetryPacket(byte[] originalDestinationConnectionId) {
        byte[] sourceConnectionId = { 0x0b, 0x0b, 0x0b, 0x0b };
        byte[] destinationConnectionId = { 0x0f, 0x0f, 0x0f, 0x0f };
        byte[] retryToken = { 0x01, 0x02, 0x03 };
        return new RetryPacket(Version.getDefault(), sourceConnectionId, destinationConnectionId, originalDestinationConnectionId, retryToken);
    }

    @Test
    void testRetryPacketWithIncorrectOriginalDestinationIdShouldBeDiscarded() throws Exception {
        Sender sender = Mockito.mock(Sender.class);
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
        RetryPacket retryPacket = createRetryPacket(new byte[] { 0x03, 0x0a, 0x0d, 0x09 });
        connection.process(retryPacket, null);

        verify(sender, never()).send(any(QuicPacket.class), anyString(), any(Consumer.class));
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
        simulateConnectionReceivingRetryPacket();

        // Simulate a TransportParametersExtension is received that does contain an original destination id
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setOriginalConnectionId(new byte[] { 0x0d, 0x0d, 0x0d, 0x0d });
        connection.setPeerTransportParameters(transportParameters);

        verify(connection).signalConnectionError(argThat(error -> error == QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR));
    }

    @Test
    void testAfterRetryPacketTransportParametersWithCorrectOriginalDestinationId() throws Exception {
        simulateConnectionReceivingRetryPacket();

        // Simulate a TransportParametersExtension is received that does contain the original destination id
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setOriginalConnectionId(originalDestinationId);
        connection.setPeerTransportParameters(transportParameters);

        verify(connection, never()).signalConnectionError(any());
    }

    @Test
    void testWithNormalConnectionTransportParametersShouldNotContainOriginalDestinationId() throws Exception {
        simulateNormalConnection();

        // Simulate a TransportParametersExtension is received that does not contain an original destination id
        connection.setPeerTransportParameters(new TransportParameters());

        verify(connection, never()).signalConnectionError(any());
    }

    @Test
    void testOnNormalConnectionTransportParametersWithOriginalDestinationIdLeadsToConnectionError() throws Exception {
        simulateNormalConnection();

        // Simulate a TransportParametersExtension is received that does contain an original destination id
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setOriginalConnectionId(new byte[] { 0x0d, 0x0d, 0x0d, 0x0d });
        connection.setPeerTransportParameters(transportParameters);

        verify(connection).signalConnectionError(argThat(error -> error == QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR));
    }

    private void simulateConnectionReceivingRetryPacket() throws Exception {
        Sender sender = Mockito.mock(Sender.class);
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

        // Store original destination id
        originalDestinationId = connection.getDestinationConnectionId();

        // Simulate a RetryPacket is received
        RetryPacket retryPacket = createRetryPacket(connection.getDestinationConnectionId());
        connection.process(retryPacket, null);
    }

    private void simulateNormalConnection() throws Exception {
        Sender sender = Mockito.mock(Sender.class);
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
    void testCreateStream() throws IOException {
        QuicConnection connection = new QuicConnection("localhost", 443, Mockito.mock(Logger.class));

        QuicStream stream = connection.createStream(true);
        int firstStreamId = stream.getStreamId();
        int streamIdLowBits = firstStreamId & 0x03;

        assertThat(streamIdLowBits).isEqualTo(0x00);

        QuicStream stream2 = connection.createStream(true);
        assertThat(stream2.getStreamId()).isEqualTo(firstStreamId + 4);
    }

    @Test
    void testConnectionFlowControl() throws Exception {
        QuicConnection connection = new QuicConnection("localhost", 443, Mockito.mock(Logger.class));
        Sender sender = Mockito.mock(Sender.class);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        long flowControlIncrement = (long) new FieldReader(connection, connection.getClass().getDeclaredField("flowControlIncrement")).read();

        connection.slideFlowControlWindow(10);
        verify(sender, never()).send(any(QuicPacket.class), anyString(), any(Consumer.class));  // No initial update, value is advertised in transport parameters.

        connection.slideFlowControlWindow((int) flowControlIncrement);
        verify(sender, times(1)).send(any(QuicPacket.class), anyString(), any(Consumer.class));

        connection.slideFlowControlWindow((int) (flowControlIncrement * 0.8));
        verify(sender, times(1)).send(any(QuicPacket.class), anyString(), any(Consumer.class));

        connection.slideFlowControlWindow((int) (flowControlIncrement * 0.21));
        verify(sender, times(2)).send(any(QuicPacket.class), anyString(), any(Consumer.class));
    }

    @Test
    void testMinimumQuicVersionIs23() {
        assertThatThrownBy(
                () -> new QuicConnection("localhost", 443, Version.IETF_draft_19, Mockito.mock(Logger.class)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testQuicVersion23IsSupported() throws Exception {
        assertThat(new QuicConnection("localhost", 443, Version.IETF_draft_23, Mockito.mock(Logger.class))).isNotNull();
    }

    @Test
    void receivingTransportParametersInitializesFlowController() {
        connection.setPeerTransportParameters(new TransportParameters(30, 9000, 1, 1));
        QuicStream stream = connection.createStream(true);
        assertThat(connection.getFlowController().increaseFlowControlLimit(stream, 9999)).isEqualTo(9000);
    }

    @Test
    void receivingMaxStreamDataFrameIncreasesFlowControlLimit() {
        TransportParameters parameters = new TransportParameters();
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
        TransportParameters parameters = new TransportParameters();
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
        Sender sender = Mockito.mock(Sender.class);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionState"), QuicConnection.Status.Connected);

        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new ConnectionCloseFrame(Version.getDefault())), Instant.now());

        verify(sender).send(argThat(new PacketMatcherByFrameClass(ConnectionCloseFrame.class)), anyString(), any(Consumer.class));
    }

    @Test
    void receivingConnectionCloseWhileConnectedResultsInReplyWithConnectionCloseOnce() throws Exception {
        Sender sender = Mockito.mock(Sender.class);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionState"), QuicConnection.Status.Connected);

        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new ConnectionCloseFrame(Version.getDefault())), Instant.now());
        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new ConnectionCloseFrame(Version.getDefault())), Instant.now());
        connection.processFrames(
                new ShortHeaderPacket(Version.getDefault(), destinationConnectionId,
                        new ConnectionCloseFrame(Version.getDefault())), Instant.now());

        verify(sender, times(1)).send(argThat(new PacketMatcherByFrameClass(ConnectionCloseFrame.class)), anyString(), any(Consumer.class));
    }

    @Test
    void closingConnectedConnectionTriggersConnectionClose() throws Exception {
        Sender sender = Mockito.mock(Sender.class);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("sender"), sender);
        FieldSetter.setField(connection, connection.getClass().getDeclaredField("connectionState"), QuicConnection.Status.Connected);

        connection.close();

        verify(sender).send(argThat(new PacketMatcherByFrameClass(ConnectionCloseFrame.class)), anyString(), any(Consumer.class));
    }
}
