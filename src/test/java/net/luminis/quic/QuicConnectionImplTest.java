/*
 * Copyright © 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic;

import net.luminis.quic.frame.*;
import net.luminis.quic.log.NullLogger;
import net.luminis.quic.packet.*;
import net.luminis.quic.send.SenderImpl;
import net.luminis.quic.QuicStream;
import net.luminis.quic.stream.StreamManager;
import net.luminis.tls.handshake.TlsEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class QuicConnectionImplTest {

    private int onePto = 40;
    private QuicConnectionImpl connection;
    private SenderImpl sender;

    @BeforeEach
    void createObjectUnderTest() throws Exception {
        sender = mock(SenderImpl.class);
        when(sender.getPto()).thenReturn(onePto);
        connection = new NonAbstractQuicConnection();
    }

    @Test
    void whenClosingNormalPacketsAreNotProcessed() {
        // Given
        connection.immediateClose(EncryptionLevel.App);

        // When
        ShortHeaderPacket packet = spy(new ShortHeaderPacket(Version.getDefault(), new byte[0], new CryptoFrame()));
        connection.process(packet, Instant.now());

        // Then
        verify(packet, never()).accept(any(PacketProcessor.class), any(Instant.class));
    }

    @Test
    void whenClosingNormalPacketLeadsToSendingConnectionClose() {
        // Given
        connection.immediateClose(EncryptionLevel.App);
        clearInvocations(sender);

        // When
        ShortHeaderPacket packet = spy(new ShortHeaderPacket(Version.getDefault(), new byte[0], new CryptoFrame()));
        connection.processPacket(Instant.now(), packet);

        // Then
        verify(sender, atLeast(1)).send(argThat(f -> f instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void whenClosingStreamsAreClosed() {
        // Given

        // When
        connection.immediateClose(EncryptionLevel.App);

        // Then
        verify(connection.getStreamManager()).abortAll();
    }

    @Test
    void whenReceivingCloseOneCloseIsSend() {
        // When
        connection.handlePeerClosing(new ConnectionCloseFrame(Version.getDefault(), 0, null), EncryptionLevel.App);

        // Then
        verify(sender, atLeast(1)).send(argThat(f -> f instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));
    }

    @Test
    void whenReceivingCloseNormalPacketsAreNotProcessed() {
        // When
        connection.handlePeerClosing(new ConnectionCloseFrame(Version.getDefault(), 0, null), EncryptionLevel.App);

        // When
        ShortHeaderPacket packet = spy(new ShortHeaderPacket(Version.getDefault(), new byte[0], new CryptoFrame()));
        connection.process(packet, Instant.now());

        // Then
        verify(packet, never()).accept(any(PacketProcessor.class), any(Instant.class));
    }

    @Test
    void afterThreePtoConnectionIsTerminated() throws Exception {
        // Given
        connection.immediateClose(EncryptionLevel.App);

        // When
        Thread.sleep(2 * onePto);
        assertThat(((NonAbstractQuicConnection) connection).terminated).isFalse();

        Thread.sleep(2 * onePto);

        // Then
        assertThat(((NonAbstractQuicConnection) connection).terminated).isTrue();
    }

    @Test
    void whenPeerClosingAfterThreePtoConnectionIsTerminated() throws Exception {
        // When
        connection.handlePeerClosing(new ConnectionCloseFrame(Version.getDefault(), 0, null), EncryptionLevel.App);

        // When
        Thread.sleep(2 * onePto);
        assertThat(((NonAbstractQuicConnection) connection).terminated).isFalse();

        Thread.sleep(2 * onePto);

        // Then
        assertThat(((NonAbstractQuicConnection) connection).terminated).isTrue();
    }

    @Test
    void inClosingStateNumberOfConnectionClosePacketsSendShouldBeRateLimited() {
        // Given
        connection.immediateClose(EncryptionLevel.App);

        // When
        ShortHeaderPacket packet = new ShortHeaderPacket(Version.getDefault(), new byte[0], new CryptoFrame());
        for (int i = 0; i < 100; i++) {
            connection.processPacket(Instant.now(), packet);
        }

        // Then
        verify(sender, atMost(50)).send(argThat(f -> f instanceof ConnectionCloseFrame), any(EncryptionLevel.class), any(Consumer.class));

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
        public void process(QuicFrame frame, QuicPacket packet, Instant timeReceived) {
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
        public void registerProcessor(FrameProcessor2<AckFrame> processor) {
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
        public QuicStream createStream(boolean bidirectional) {
            return null;
        }

        @Override
        public void setPeerInitiatedStreamCallback(Consumer<QuicStream> streamConsumer) {
        }
    }
}
