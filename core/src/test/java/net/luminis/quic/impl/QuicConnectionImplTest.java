/*
 * Copyright © 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.impl;

import net.luminis.quic.ConnectionListener;
import net.luminis.quic.ConnectionTerminatedEvent;
import net.luminis.quic.QuicConstants;
import net.luminis.quic.QuicStream;
import net.luminis.quic.ack.GlobalAckGenerator;
import net.luminis.quic.cid.ConnectionIdManager;
import net.luminis.quic.common.EncryptionLevel;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.NullLogger;
import net.luminis.quic.packet.*;
import net.luminis.quic.send.SenderImpl;
import net.luminis.quic.stream.StreamManager;
import net.luminis.quic.test.FieldSetter;
import net.luminis.quic.test.TestClock;
import net.luminis.quic.test.TestScheduledExecutor;
import net.luminis.tls.engine.TlsEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.function.Consumer;

import static net.luminis.quic.ConnectionTerminatedEvent.CloseReason.IdleTimeout;
import static net.luminis.quic.ConnectionTerminatedEvent.CloseReason.ImmediateClose;
import static net.luminis.quic.common.EncryptionLevel.App;
import static net.luminis.quic.common.EncryptionLevel.Handshake;
import static net.luminis.quic.common.EncryptionLevel.Initial;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class QuicConnectionImplTest {

    private int onePto = 40;
    private QuicConnectionImpl connection;
    private SenderImpl sender;
    private TestClock testClock;
    private TestScheduledExecutor scheduler;
    private TestScheduledExecutor callbackExecutor;

    @BeforeEach
    void createObjectUnderTest() throws Exception {
        sender = mock(SenderImpl.class);
        when(sender.getPto()).thenReturn(onePto);
        connection = new NonAbstractQuicConnection();
        testClock = new TestClock();
        scheduler = new TestScheduledExecutor(testClock);
        FieldSetter.setField(connection, QuicConnectionImpl.class.getDeclaredField("scheduler"), scheduler);
        callbackExecutor = new TestScheduledExecutor(testClock);
        FieldSetter.setField(connection, QuicConnectionImpl.class.getDeclaredField("callbackThread"), callbackExecutor);
    }

    //region close
    @Test
    void whenClosingNormalPacketsAreNotProcessed() {
        // Given
        PacketFilter packetProcessor = wrapWithClosingOrDrainingFilter(connection);
        connection.immediateClose();

        // When
        ShortHeaderPacket packet = spy(new ShortHeaderPacket(Version.getDefault(), new byte[0], new CryptoFrame()));
        packetProcessor.processPacket(packet, metaDataForNow());

        // Then
        verify(packet, never()).accept(any(PacketProcessor.class), any(Instant.class));
    }

    @Test
    void whenClosingDuringInitialNormalPacketsAreNotProcessed() {
        // Given
        PacketFilter packetProcessor = wrapWithClosingOrDrainingFilter(connection);
        connection.immediateClose();
        connection.runPostProcessingActions();

        // When
        InitialPacket packet = spy(new InitialPacket(Version.getDefault(), new byte[0], new byte[0], new byte[0], new CryptoFrame()));
        packetProcessor.processPacket(packet, metaDataForNow());

        // Then
        verify(packet, never()).accept(any(PacketProcessor.class), any(Instant.class));
    }

    @Test
    void whenClosingNormalPacketLeadsToSendingConnectionClose() {
        // Given
        PacketFilter packetProcessor = wrapWithClosingOrDrainingFilter(connection);
        connection.immediateClose();
        clearInvocations(sender);

        // When
        ShortHeaderPacket packet = spy(new ShortHeaderPacket(Version.getDefault(), new byte[0], new CryptoFrame()));
        packetProcessor.processPacket(packet, metaDataForNow());

        // Then
        verify(sender, atLeast(1)).send(argThat(f -> f instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void whenClosingNormalPacketLeadsToSendingConnectionCloseWithSameErrorInfo() {
        // Given
        PacketFilter packetProcessor = wrapWithClosingOrDrainingFilter(connection);
        connection.immediateCloseWithError(QuicConstants.TransportErrorCode.INTERNAL_ERROR.value, "something went wrong");
        clearInvocations(sender);

        // When
        ShortHeaderPacket packet = spy(new ShortHeaderPacket(Version.getDefault(), new byte[0], new CryptoFrame()));
        packetProcessor.processPacket(packet, metaDataForNow());

        // Then
        ArgumentCaptor<QuicFrame> frameCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(sender).send(frameCaptor.capture(), any(EncryptionLevel.class), any(Consumer.class));
        assertThat(((ConnectionCloseFrame) frameCaptor.getValue()).getErrorCode()).isEqualTo(QuicConstants.TransportErrorCode.INTERNAL_ERROR.value);
    }

    @Test
    void whenClosingStreamsAreClosed() {
        // Given

        // When
        connection.immediateClose();

        // Then
        verify(connection.getStreamManager()).abortAll();
    }

    @Test
    void whenPeerIsClosingStreamsShouldBeAborted() {
        // Given

        // When
        connection.handlePeerClosing(new ConnectionCloseFrame(Version.getDefault(), 0, "no error"), App);

        // Then
        verify(connection.getStreamManager()).abortAll();
    }

    @Test
    void whenReceivingCloseOneCloseIsSend() {
        // When
        connection.handlePeerClosing(new ConnectionCloseFrame(Version.getDefault(), 0, null), App);

        // Then
        verify(sender, atLeast(1)).send(argThat(f -> f instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void whenReceivingCloseNormalPacketsAreNotProcessed() {
        // Given
        PacketFilter packetProcessor = wrapWithClosingOrDrainingFilter(connection);
        connection.handlePeerClosing(new ConnectionCloseFrame(Version.getDefault(), 0, null), App);

        // When
        ShortHeaderPacket packet = spy(new ShortHeaderPacket(Version.getDefault(), new byte[0], new CryptoFrame()));
        packetProcessor.processPacket(packet, metaDataForNow());

        // Then
        verify(packet, never()).accept(any(PacketProcessor.class), any(Instant.class));
    }

    @Test
    void afterThreePtoConnectionIsTerminated() throws Exception {
        // Given
        connectionEncryptionLevel(App);
        connection.immediateClose();

        // When
        testClock.fastForward(11 * onePto / 4);
        assertThat(((NonAbstractQuicConnection) connection).terminated).isFalse();

        testClock.fastForward((12 - 1) * onePto / 4);

        // Then
        assertThat(((NonAbstractQuicConnection) connection).terminated).isTrue();
    }

    @Test
    void whenPeerClosingAfterThreePtoConnectionIsTerminated() throws Exception {
        // When
        connection.handlePeerClosing(new ConnectionCloseFrame(Version.getDefault(), 0, null), App);

        // When
        testClock.fastForward(11 * onePto / 4);
        assertThat(((NonAbstractQuicConnection) connection).terminated).isFalse();

        testClock.fastForward((12 - 1) * onePto / 4);

        // Then
        assertThat(((NonAbstractQuicConnection) connection).terminated).isTrue();
    }

    @Test
    void inClosingStateNumberOfConnectionClosePacketsSendShouldBeRateLimited() {
        // Given
        connection.immediateClose();

        // When
        ShortHeaderPacket packet = new ShortHeaderPacket(Version.getDefault(), new byte[0], new CryptoFrame());
        for (int i = 0; i < 100; i++) {
            connection.processPacket(packet, metaDataForNow());
        }

        // Then
        verify(sender, atMost(50)).send(argThat(f -> f instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void applicationCloseWithErrorSendsConnectionCloseFrame1d() throws Exception {
        // Given
        connectionEncryptionLevel(App);

        // When
        connection.close(999, "application error induced close");

        // Then
        verify(sender, atLeast(1)).send(
                argThat(f -> f instanceof ConnectionCloseFrame && ((ConnectionCloseFrame) f).getFrameType() == 0x1d),
                any(EncryptionLevel.class) );
    }

    @Test
    void whenConnectionIsClosedDuringHandshakeConnectionCloseFrameIsSentOnTwoLevels() throws Exception {
        connectionEncryptionLevel(Handshake);

        // When
        connection.close(QuicConstants.TransportErrorCode.INTERNAL_ERROR, "something went wrong");

        // Then
        ArgumentCaptor<QuicFrame> frameCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        ArgumentCaptor<EncryptionLevel> levelCaptor = ArgumentCaptor.forClass(EncryptionLevel.class);
        verify(sender, atLeast(2)).send(frameCaptor.capture(), levelCaptor.capture());

        assertThat(frameCaptor.getAllValues()).hasOnlyElementsOfType(ConnectionCloseFrame.class);
        assertThat(levelCaptor.getAllValues()).containsExactlyInAnyOrder(Handshake, Initial);
    }

    @Test
    void whenConnectionIsClosedWithAppErrorDuringHandshakeConnectionCloseFrame1cIsSent() throws Exception {
        connectionEncryptionLevel(Handshake);

        // When
        connection.close(999, "application error induced close");

        // Then
        verify(sender, atLeast(1)).send(
                argThat(f -> f instanceof ConnectionCloseFrame && ((ConnectionCloseFrame) f).getFrameType() == 0x1c),
                any(EncryptionLevel.class) );
    }

    @Test
    void afterCloseIdleTimerIsShutdown() throws Exception {
        // Given
        connectionEncryptionLevel(App);
        IdleTimer idleTimer = mock(IdleTimer.class);
        FieldSetter.setField(connection, QuicConnectionImpl.class.getDeclaredField("idleTimer"), idleTimer);

        // When
        connection.close();
        testClock.fastForward(3 * onePto);

        // Then
        verify(idleTimer).shutdown();
    }
    //endregion

    //region close events
    @Test
    void whenClosingConnectionItShouldFireDisconnectEvent() {
        // Given
        ConnectionListener closeCallback = mock(ConnectionListener.class);
        ArgumentCaptor<ConnectionTerminatedEvent> eventCaptor = ArgumentCaptor.forClass(ConnectionTerminatedEvent.class);
        connection.setConnectionListener(closeCallback);

        // When
        connection.close();
        callbackExecutor.clockAdvanced();

        // Then
        verify(closeCallback).disconnected(eventCaptor.capture());
        assertThat(eventCaptor.getValue().closeReason()).isEqualTo(ImmediateClose);
        assertThat(eventCaptor.getValue().closedByPeer()).isFalse();
        assertThat(eventCaptor.getValue().hasApplicationError()).isFalse();
        assertThat(eventCaptor.getValue().hasTransportError()).isFalse();
        assertThat(eventCaptor.getValue().hasError()).isFalse();
    }

    @Test
    void whenClosingDueToIdleTimeoutItShouldFireDisconnectEvent() {
        // Given
        ConnectionListener closeCallback = mock(ConnectionListener.class);
        ArgumentCaptor<ConnectionTerminatedEvent> eventCaptor = ArgumentCaptor.forClass(ConnectionTerminatedEvent.class);
        connection.setConnectionListener(closeCallback);

        // When
        connection.silentlyCloseConnection(30_000);
        callbackExecutor.clockAdvanced();

        // Then
        verify(closeCallback).disconnected(eventCaptor.capture());
        assertThat(eventCaptor.getValue().closeReason()).isEqualTo(IdleTimeout);
        assertThat(eventCaptor.getValue().hasApplicationError()).isFalse();
        assertThat(eventCaptor.getValue().hasTransportError()).isFalse();
        assertThat(eventCaptor.getValue().hasError()).isFalse();
    }

    @Test
    void whenClosingWithTransportErrorItShouldFireDisconnectEvent() {
        // Given
        ConnectionListener closeCallback = mock(ConnectionListener.class);
        ArgumentCaptor<ConnectionTerminatedEvent> eventCaptor = ArgumentCaptor.forClass(ConnectionTerminatedEvent.class);
        connection.setConnectionListener(closeCallback);

        // When
        connection.close(QuicConstants.TransportErrorCode.FLOW_CONTROL_ERROR, "flow control error");
        callbackExecutor.clockAdvanced();

        // Then
        verify(closeCallback).disconnected(eventCaptor.capture());
        assertThat(eventCaptor.getValue().closeReason()).isEqualTo(ImmediateClose);
        assertThat(eventCaptor.getValue().hasTransportError()).isTrue();
        assertThat(eventCaptor.getValue().transportErrorCode()).isEqualTo(QuicConstants.TransportErrorCode.FLOW_CONTROL_ERROR.value);
        assertThat(eventCaptor.getValue().hasApplicationError()).isFalse();
        assertThat(eventCaptor.getValue().hasError()).isTrue();
    }

    @Test
    void whenClosingWithApplicationErrorItShouldFireDisconnectEvent() {
        // Given
        ConnectionListener closeCallback = mock(ConnectionListener.class);
        ArgumentCaptor<ConnectionTerminatedEvent> eventCaptor = ArgumentCaptor.forClass(ConnectionTerminatedEvent.class);
        connection.setConnectionListener(closeCallback);

        // When
        connection.close(999, "application error induced close");
        callbackExecutor.clockAdvanced();

        // Then
        verify(closeCallback).disconnected(eventCaptor.capture());
        assertThat(eventCaptor.getValue().closeReason()).isEqualTo(ImmediateClose);
        assertThat(eventCaptor.getValue().hasApplicationError()).isTrue();
        assertThat(eventCaptor.getValue().applicationErrorCode()).isEqualTo(999);
        assertThat(eventCaptor.getValue().hasTransportError()).isFalse();
        assertThat(eventCaptor.getValue().hasError()).isTrue();
    }

    @Test
    void whenPeerClosedConnectionItShouldFireDisconnectEvent() {
        // Given
        ConnectionListener closeCallback = mock(ConnectionListener.class);
        ArgumentCaptor<ConnectionTerminatedEvent> eventCaptor = ArgumentCaptor.forClass(ConnectionTerminatedEvent.class);
        connection.setConnectionListener(closeCallback);

        // When
        connection.handlePeerClosing(new ConnectionCloseFrame(Version.getDefault(), QuicConstants.TransportErrorCode.NO_ERROR.value, null), App);
        callbackExecutor.clockAdvanced();

        verify(closeCallback).disconnected(eventCaptor.capture());
        assertThat(eventCaptor.getValue().closeReason()).isEqualTo(ImmediateClose);
        assertThat(eventCaptor.getValue().closedByPeer()).isTrue();
        assertThat(eventCaptor.getValue().hasApplicationError()).isFalse();
        assertThat(eventCaptor.getValue().hasTransportError()).isFalse();
        assertThat(eventCaptor.getValue().hasError()).isFalse();
    }

    @Test
    void whenPeerClosedWithTransportErrorItShouldFireDisconnectEvent() {
        // Given
        ConnectionListener closeCallback = mock(ConnectionListener.class);
        ArgumentCaptor<ConnectionTerminatedEvent> eventCaptor = ArgumentCaptor.forClass(ConnectionTerminatedEvent.class);
        connection.setConnectionListener(closeCallback);

        // When
        connection.handlePeerClosing(new ConnectionCloseFrame(Version.getDefault(), QuicConstants.TransportErrorCode.INTERNAL_ERROR.value, null), App);
        callbackExecutor.clockAdvanced();

        verify(closeCallback).disconnected(eventCaptor.capture());
        assertThat(eventCaptor.getValue().closeReason()).isEqualTo(ImmediateClose);
        assertThat(eventCaptor.getValue().closedByPeer()).isTrue();
        assertThat(eventCaptor.getValue().hasTransportError()).isTrue();
        assertThat(eventCaptor.getValue().transportErrorCode()).isEqualTo(QuicConstants.TransportErrorCode.INTERNAL_ERROR.value);
        assertThat(eventCaptor.getValue().hasApplicationError()).isFalse();
        assertThat(eventCaptor.getValue().hasError()).isTrue();
    }

    @Test
    void whenPeerClosedWithApplicationErrorItShouldFireDisconnectEvent() {
        // Given
        ConnectionListener closeCallback = mock(ConnectionListener.class);
        ArgumentCaptor<ConnectionTerminatedEvent> eventCaptor = ArgumentCaptor.forClass(ConnectionTerminatedEvent.class);
        connection.setConnectionListener(closeCallback);

        // When
        connection.handlePeerClosing(new ConnectionCloseFrame(Version.getDefault(), 999, false, "application error"), App);
        callbackExecutor.clockAdvanced();

        // Then
        verify(closeCallback).disconnected(eventCaptor.capture());
        assertThat(eventCaptor.getValue().closeReason()).isEqualTo(ImmediateClose);
        assertThat(eventCaptor.getValue().closedByPeer()).isTrue();
        assertThat(eventCaptor.getValue().hasApplicationError()).isTrue();
        assertThat(eventCaptor.getValue().applicationErrorCode()).isEqualTo(999);
        assertThat(eventCaptor.getValue().hasTransportError()).isFalse();
        assertThat(eventCaptor.getValue().hasError()).isTrue();
    }

    @Test
    void whenCloseIsCalledMultipleTimesListenerShouldOnlyBeCalledOnce() {
        // Given
        ConnectionListener listener = mock(ConnectionListener.class);
        connection.setConnectionListener(listener);

        // When
        connection.close();
        callbackExecutor.clockAdvanced();
        connection.close();
        callbackExecutor.clockAdvanced();
        connection.close();
        callbackExecutor.clockAdvanced();

        // Then
        verify(listener, times(1)).disconnected(any(ConnectionTerminatedEvent.class));
    }


    @Test
    void whenClosingIdleTimeoutCloseShouldBeIgnored() {
        // Given
        ConnectionListener listener = mock(ConnectionListener.class);
        connection.setConnectionListener(listener);
        connection.immediateClose();
        scheduler.clockAdvanced();

        // When
        connection.silentlyCloseConnection(30_000);
        callbackExecutor.clockAdvanced();

        // Then
        verify(listener, times(1)).disconnected(any(ConnectionTerminatedEvent.class));
    }

    //endregion

    //region RFC 9221 Datagram Extension
    @Test
    void whenDatagramExtensionIsRequiredReceivingTransportParameterShouldEnableIt() {
        // Given
        connection.enableDatagramExtension();
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setMaxDatagramFrameSize(65535);

        // When
        connection.processCommonTransportParameters(transportParameters);

        // Then
        assertThat(connection.canSendDatagram()).isTrue();
        assertThat(connection.canReceiveDatagram()).isTrue();
        assertThat(connection.isDatagramExtensionEnabled()).isTrue();
    }

    @Test
    void whenDatagramExtensionIsRequiredNotReceivingTransportParameterShouldNotEnableIt() {
        // Given
        connection.enableDatagramExtension();
        TransportParameters transportParameters = new TransportParameters();

        // When
        connection.processCommonTransportParameters(transportParameters);

        // Then
        assertThat(connection.canSendDatagram()).isFalse();
        assertThat(connection.canReceiveDatagram()).isTrue();
        assertThat(connection.isDatagramExtensionEnabled()).isFalse();
    }

    @Test
    void whenDatagramExtensionIsNotRequiredReceivingTransportParameterShouldNotEnableIt() {
        // Given
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setMaxDatagramFrameSize(65535);

        // When
        connection.processCommonTransportParameters(transportParameters);

        // Then
        assertThat(connection.canSendDatagram()).isFalse();
        assertThat(connection.canReceiveDatagram()).isFalse();
        assertThat(connection.isDatagramExtensionEnabled()).isFalse();
    }

    @Test
    void whenDatagramExtensionIsEnabledMaxDatagramFrameSizeShouldHaveNonZeroValue() {
        // Given
        connection.enableDatagramExtension();
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setMaxDatagramFrameSize(65535);

        // When
        connection.processCommonTransportParameters(transportParameters);

        // Then
        assertThat(connection.getMaxDatagramFrameSize()).isGreaterThan(0);
    }

    @Test
    void whenDatagramExtensionIsEnabledMaxDatagramFrameIsMaximizedTo65535() {
        // Given
        connection.enableDatagramExtension();
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setMaxDatagramFrameSize(4294967296L);

        // When
        connection.processCommonTransportParameters(transportParameters);

        // Then
        assertThat(connection.getMaxDatagramFrameSize()).isEqualTo(65535);
    }

    @Test
    void smallDatagramShouldBeSent() {
        // Given
        datagramExtensionIsEnabled();

        // When
        connection.sendDatagram(new byte[16]);

        // Then
        verify(sender).sendWithPriority(any(QuicFrame.class), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void emptyDatagramShouldBeSent() {
        // Given
        datagramExtensionIsEnabled();

        // When
        connection.sendDatagram(new byte[0]);

        // Then
        verify(sender).sendWithPriority(any(QuicFrame.class), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void whenDatagramIsLargerThanMaxSendingDatagramShouldBeRejected() {
        // Given
        datagramExtensionIsEnabled();

        assertThatThrownBy(() ->
                // When
                connection.sendDatagram(new byte[1252]))
                // Then
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void whenDatagramIsLargerThanMaxAllowedByPeerSendingShouldBeRejected() {
        // Given
        datagramExtensionIsEnabled(1000);

        assertThatThrownBy(() ->
                // When
                connection.sendDatagram(new byte[1001]))
                // Then
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void whenDatagramIsReceivedTheHandlerShouldBeCalled() throws Exception {
        // Given
        datagramExtensionIsEnabled(1000);
        Consumer handler = mock(Consumer.class);
        connection.setDatagramHandler(handler, scheduler);
        DatagramFrame datagramFrame = new DatagramFrame(new byte[] { 0x01, 0x02, 0x03 });

        // When
        connection.process(datagramFrame, mock(QuicPacket.class), Instant.now());
        scheduler.clockAdvanced();

        // Then
        verify(handler).accept(datagramFrame.getData());
    }

    @Test
    void whenReceivingDatagramWhenNotEnabeldConnectionShouldBeTerminatedWithAnError() throws Exception {
        // Given
        connectionEncryptionLevel(App);
        DatagramFrame datagramFrame = new DatagramFrame(new byte[16]);

        // When
        connection.process(datagramFrame, mock(QuicPacket.class), Instant.now());

        // Then
        testClock.fastForward(3 * onePto);

        assertThat(((NonAbstractQuicConnection) connection).terminated).isTrue();
    }
    //endregion

    //region helper methods
    private PacketMetaData metaDataForNow() {
        InetSocketAddress sourceAddress = new InetSocketAddress(52719);
        return new PacketMetaData(Instant.now(), sourceAddress, 0);
    }

    private PacketFilter wrapWithClosingOrDrainingFilter(QuicConnectionImpl connection) {
        return connection.new ClosingOrDrainingFilter(connection, null);
    }

    private void datagramExtensionIsEnabled() {
        datagramExtensionIsEnabled(65535);
    }

    private void datagramExtensionIsEnabled(int maxDatagramFrameSize) {
        connection.enableDatagramExtension();
        TransportParameters transportParameters = new TransportParameters();
        transportParameters.setMaxDatagramFrameSize(maxDatagramFrameSize);
        connection.processCommonTransportParameters(transportParameters);
    }

    private void connectionEncryptionLevel(EncryptionLevel level) throws Exception {
        FieldSetter.setField(connection, QuicConnectionImpl.class.getDeclaredField("currentEncryptionLevel"), level);
    }

    class NonAbstractQuicConnection extends QuicConnectionImpl {
        private final StreamManager streamManager;
        public boolean terminated;

        NonAbstractQuicConnection() {
            super(Version.getDefault(), Role.Server, null, new NullLogger());
            idleTimer = new IdleTimer(this, log);
            streamManager = mock(StreamManager.class);
        }

       @Override
        protected void terminate() {
            super.terminate();
            terminated = true;
        }

        @Override
        public void process(AckFrame ackFrame, QuicPacket packet, Instant timeReceived) {
        }

        @Override
        public void process(ConnectionCloseFrame connectionCloseFrame, QuicPacket packet, Instant timeReceived) {
        }

        @Override
        public void process(CryptoFrame cryptoFrame, QuicPacket packet, Instant timeReceived) {
        }

        @Override
        protected void cryptoProcessingErrorOcurred(Exception exception) {
        }

        @Override
        public void process(DataBlockedFrame dataBlockedFrame, QuicPacket packet, Instant timeReceived) {
        }

        @Override
        public void process(HandshakeDoneFrame handshakeDoneFrame, QuicPacket packet, Instant timeReceived) {
        }

        @Override
        public void process(MaxDataFrame maxDataFrame, QuicPacket packet, Instant timeReceived) {
        }

        @Override
        public void process(MaxStreamDataFrame maxStreamDataFrame, QuicPacket packet, Instant timeReceived) {
        }

        @Override
        public void process(MaxStreamsFrame maxStreamsFrame, QuicPacket packet, Instant timeReceived) {
        }

        @Override
        public void process(NewConnectionIdFrame newConnectionIdFrame, QuicPacket packet, Instant timeReceived) {
        }

        @Override
        public void process(NewTokenFrame newTokenFrame, QuicPacket packet, Instant timeReceived) {

        }

        @Override
        public void process(Padding paddingFrame, QuicPacket packet, Instant timeReceived) {

        }

        @Override
        public void process(PathChallengeFrame pathChallengeFrame, QuicPacket packet, Instant timeReceived) {
        }

        @Override
        public void process(PathResponseFrame pathResponseFrame, QuicPacket packet, Instant timeReceived) {

        }

        @Override
        public void process(PingFrame pingFrame, QuicPacket packet, Instant timeReceived) {

        }

        @Override
        public void process(ResetStreamFrame resetStreamFrame, QuicPacket packet, Instant timeReceived) {

        }

        @Override
        public void process(RetireConnectionIdFrame retireConnectionIdFrame, QuicPacket packet, Instant timeReceived) {
        }

        @Override
        public void process(StopSendingFrame stopSendingFrame, QuicPacket packet, Instant timeReceived) {

        }

        @Override
        public void process(StreamFrame streamFrame, QuicPacket packet, Instant timeReceived) {
        }

        @Override
        public void process(StreamDataBlockedFrame streamDataBlockedFrame, QuicPacket packet, Instant timeReceived) {

        }

        @Override
        public void process(StreamsBlockedFrame streamsBlockedFrame, QuicPacket packet, Instant timeReceived) {

        }

        @Override
        public ProcessResult process(InitialPacket packet, Instant time) {
            return null;
        }

        @Override
        public ProcessResult process(ShortHeaderPacket packet, Instant time) {
            processFrames(packet, time);
            return null;
        }

        @Override
        public ProcessResult process(VersionNegotiationPacket packet, Instant time) {
            return null;
        }

        @Override
        public ProcessResult process(HandshakePacket packet, Instant time) {
            return null;
        }

        @Override
        public ProcessResult process(RetryPacket packet, Instant time) {
            return null;
        }

        @Override
        public ProcessResult process(ZeroRttPacket packet, Instant time) {
            return null;
        }

        @Override
        protected int getSourceConnectionIdLength() {
            return 0;
        }

        @Override
        public void abortConnection(Throwable error) {
        }

        @Override
        protected SenderImpl getSender() {
            return sender;
        }

        @Override
        protected TlsEngine getTlsEngine() {
            return null;
        }

        @Override
        protected GlobalAckGenerator getAckGenerator() {
            return mock(GlobalAckGenerator.class);
        }

        @Override
        protected StreamManager getStreamManager() {
            return streamManager;
        }

        @Override
        protected ConnectionIdManager getConnectionIdManager() {
            return null;
        }

        @Override
        public long getInitialMaxStreamData() {
            return 0;
        }

        @Override
        public int getMaxShortHeaderPacketOverhead() {
            return 0;
        }

        @Override
        public byte[] getSourceConnectionId() {
            return new byte[0];
        }

        @Override
        public byte[] getDestinationConnectionId() {
            return new byte[0];
        }

        @Override
        public void setMaxAllowedBidirectionalStreams(int max) {
        }

        @Override
        public void setMaxAllowedUnidirectionalStreams(int max) {
        }

        @Override
        public void setDefaultStreamReceiveBufferSize(long size) {
        }

        @Override
        public void setDefaultUnidirectionalStreamReceiveBufferSize(long size) {
        }

        @Override
        public void setDefaultBidirectionalStreamReceiveBufferSize(long size) {
        }

        @Override
        public QuicStream createStream(boolean bidirectional) {
            return null;
        }

        @Override
        public void setPeerInitiatedStreamCallback(Consumer<QuicStream> streamConsumer) {
        }

        protected CheckDestinationFilter createProcessorChain() {
            return new CheckDestinationFilter(
                    new DropDuplicatePacketsFilter(
                            new PostProcessingFilter(
                                    new QlogPacketFilter(
                                            new ClosingOrDrainingFilter(this, log)))));
        }
    }
    //endregion
}
