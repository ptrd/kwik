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

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.function.Consumer;

import static net.luminis.quic.common.EncryptionLevel.App;
import static net.luminis.quic.common.EncryptionLevel.Initial;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class QuicConnectionImplTest {

    private int onePto = 40;
    private QuicConnectionImpl connection;
    private SenderImpl sender;
    private TestClock testClock;
    private TestScheduledExecutor testExecutor;

    @BeforeEach
    void createObjectUnderTest() throws Exception {
        sender = mock(SenderImpl.class);
        when(sender.getPto()).thenReturn(onePto);
        connection = new NonAbstractQuicConnection();
        testClock = new TestClock();
        testExecutor = new TestScheduledExecutor(testClock);
        FieldSetter.setField(connection, QuicConnectionImpl.class.getDeclaredField("scheduler"), testExecutor);
    }

    //region close
    @Test
    void whenClosingNormalPacketsAreNotProcessed() {
        // Given
        PacketFilter packetProcessor = wrapWithClosingOrDrainingFilter(connection);
        connection.immediateClose(App);

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
        connection.immediateClose(Initial);
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
        connection.immediateClose(App);
        clearInvocations(sender);

        // When
        ShortHeaderPacket packet = spy(new ShortHeaderPacket(Version.getDefault(), new byte[0], new CryptoFrame()));
        packetProcessor.processPacket(packet, metaDataForNow());

        // Then
        verify(sender, atLeast(1)).send(argThat(f -> f instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void whenClosingStreamsAreClosed() {
        // Given

        // When
        connection.immediateClose(App);

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
        connection.immediateClose(App);

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
        connection.immediateClose(App);

        // When
        ShortHeaderPacket packet = new ShortHeaderPacket(Version.getDefault(), new byte[0], new CryptoFrame());
        for (int i = 0; i < 100; i++) {
            connection.processPacket(packet, metaDataForNow());
        }

        // Then
        verify(sender, atMost(50)).send(argThat(f -> f instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void applicationCloseWithErrorSendsConnectionCloseFrame1d() {
        // Given

        // When
        connection.close(999, "application error induced close");

        // Then
        verify(sender, atLeast(1)).send(
                argThat(f -> f instanceof ConnectionCloseFrame && ((ConnectionCloseFrame) f).getFrameType() == 0x1d),
                any(EncryptionLevel.class) );
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
        connection.setDatagramHandler(handler, testExecutor);
        DatagramFrame datagramFrame = new DatagramFrame(new byte[] { 0x01, 0x02, 0x03 });

        // When
        connection.process(datagramFrame, mock(QuicPacket.class), Instant.now());
        testExecutor.clockAdvanced();

        // Then
        verify(handler).accept(datagramFrame.getData());
    }

    @Test
    void whenReceivingDatagramWhenNotEnabeldConnectionShouldBeTerminatedWithAnError()  {
        // Given
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
