/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.send;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.ArgumentCaptor;
import tech.kwik.core.cid.ConnectionIdManager;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.crypto.MissingKeysException;
import tech.kwik.core.frame.AckFrame;
import tech.kwik.core.frame.CryptoFrame;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.*;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.packet.InitialPacket;
import tech.kwik.core.packet.ShortHeaderPacket;
import tech.kwik.core.socket.ClientSocketManager;
import tech.kwik.core.test.FieldReader;
import tech.kwik.core.test.FieldSetter;
import tech.kwik.core.test.TestClock;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static tech.kwik.core.impl.TestUtils.getArbitraryLocalAddress;

class SenderImplTest extends AbstractSenderTest {

    private TestClock clock;
    private SenderImpl sender;
    private GlobalPacketAssembler packetAssembler;
    private ClientSocketManager socketManager;
    private InetSocketAddress clientAddress;
    private ConnectionSecrets connectionSecrets;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        clock = new TestClock();
        ConnectionIdManager connectionIdProvider = mock(ConnectionIdManager.class);
        when(connectionIdProvider.getInitialConnectionId()).thenReturn(new byte[4]);
        when(connectionIdProvider.getPeerConnectionId(any())).thenReturn(new byte[4]);
        QuicConnectionImpl connection = mock(QuicConnectionImpl.class);
        when(connection.getSourceConnectionId()).thenReturn(new byte[4]);
        when(connection.getIdleTimer()).thenReturn(new IdleTimer(connection, new NullLogger()));
        when(connection.getConnectionIdManager()).thenReturn(connectionIdProvider);
        connectionSecrets = mock(ConnectionSecrets.class);
        Aead aead = TestUtils.createKeys();
        connectionSecrets = mock(ConnectionSecrets.class);
        when(connectionSecrets.getOwnAead(any(EncryptionLevel.class))).thenReturn(aead);

        socketManager = mock(ClientSocketManager.class);
        when(socketManager.getClientAddress()).thenReturn(new InetSocketAddress(InetAddress.getLoopbackAddress(), 4433));
        sender = new SenderImpl(clock, new VersionHolder(Version.getDefault()), 1200, socketManager, connection, "", 100, new NullLogger());
        FieldSetter.setField(sender, sender.getClass().getDeclaredField("connectionSecrets"), connectionSecrets);
        
        clientAddress = getArbitraryLocalAddress();
    }

    @Test
    void whenAckWithDelayIsQueuedSenderIsWakedUpAfterDelay() {
        // Given
        sender.enableAllLevels();

        // When
        sender.sendAck(PnSpace.App, 50);
        sender.packetProcessed(false);

        // Then
        long delay = sender.determineMaximumWaitTime();
        assertThat(delay).isBetween(49L, 51L);
    }

    @Test
    void senderStatisticsShouldWork() throws Exception {
        ShortHeaderPacket packet1 = new ShortHeaderPacket(Version.getDefault(), new byte[4], new StreamFrame(0, new byte[1100], false));
        ShortHeaderPacket packet2 = new ShortHeaderPacket(Version.getDefault(), new byte[4], new StreamFrame(0, new byte[11], false));
        packet1.setPacketNumber(10);
        sender.send(List.of(new SendItem(packet1, clientAddress)));
        packet1.setPacketNumber(11);
        packet2.setPacketNumber(12);
        sender.send(List.of(new SendItem(packet1, clientAddress), new SendItem(packet2, clientAddress)));

        assertThat(sender.getStatistics().datagramsSent()).isEqualTo(2);
        assertThat(sender.getStatistics().packetsSent()).isEqualTo(3);
        assertThat(sender.getStatistics().bytesSent()).isBetween(2200l, 2300l);
    }

    @Test
    void addingProbeToDiscardedSpaceDiscardsIt() throws Exception {
        // Given
        SendRequestQueue[] senderQueues = (SendRequestQueue[]) new FieldReader(sender, sender.getClass().getDeclaredField("sendRequestQueue")).read();

        sender.discard(PnSpace.Initial, "test");

        // When
        sender.sendProbe(EncryptionLevel.Initial);

        // Then
        assertThat(senderQueues[EncryptionLevel.Initial.ordinal()].hasProbe()).isFalse();
        assertThat(senderQueues[EncryptionLevel.Handshake.ordinal()].hasProbe()).isFalse();
    }

    @Test
    void whenAntiAmplificationLimitNotReachedAssemblerIsCalledWithNoLimit() throws Exception {
        // Given
        setupMockPacketAssember();
        sender.setAntiAmplificationLimit(3 * 1200);   // This is how it's initialized when client packet received

        // When
        sender.sendIfAny();

        // Then verify
        ArgumentCaptor<Integer> packetSizeCaptor = ArgumentCaptor.forClass(Integer.class);
        verify(packetAssembler, atLeastOnce()).assemble(anyInt(), packetSizeCaptor.capture(), any(InetSocketAddress.class));
        assertThat(packetSizeCaptor.getValue()).isLessThanOrEqualTo(3 * 1200);
    }

    @Test
    void whenAntiAmplificationLimitIsReachedNothingIsSentAnymore() throws Exception {
        // Given
        sender.enableAllLevels();
        sender.setAntiAmplificationLimit(3 * 1200);   // This is how it's initialized when client packet received
        for (int i = 0; i < 9; i++) {
            sender.send(new StreamFrame(0, i * 1100, new byte[1100], false), EncryptionLevel.App);
        }
        sender.flush();

        // When
        sender.sendIfAny();

        // Then   (given fixed size of StreamFrames, only three packets will fit in the limit of 3 * 1200)
        verify(socketManager, times(3)).send(any(ByteBuffer.class), any(InetSocketAddress.class));
    }

    private void setupMockPacketAssember() throws Exception {
        packetAssembler = mock(GlobalPacketAssembler.class);
        when(packetAssembler.assemble(anyInt(), anyInt(), any(InetSocketAddress.class)))
                .thenReturn(List.of(new SendItem(new MockPacket(0, 1200, ""), clientAddress)));
        when(packetAssembler.nextDelayedSendTime()).thenReturn(Optional.empty());
        FieldSetter.setField(sender, sender.getClass().getDeclaredField("packetAssembler"), packetAssembler);
    }

    @Test
    @Timeout(value = 500, unit = TimeUnit.MILLISECONDS)
    void whenNothingIsQueuedNothingIsSentWhenPacketProcessedIsCalled()  throws Exception {
        // Given

        // When
        sender.packetProcessed(false);
        sender.doLoopIteration();

        // Then
        verify(socketManager, never()).send(any(ByteBuffer.class), any(InetSocketAddress.class));
    }

    @Test
    @Timeout(value = 500, unit = TimeUnit.MILLISECONDS)
    void whenPacketProcessedIsCalledQueuedFramesAreSent() throws Exception {
        // Given
        sender.send(new PingFrame(), EncryptionLevel.Handshake);

        // When
        sender.packetProcessed(false);
        sender.doLoopIteration();

        // Then
        verify(socketManager).send(any(ByteBuffer.class), any(InetSocketAddress.class));
    }

    @Test
    @Timeout(value = 500, unit = TimeUnit.MILLISECONDS)
    void probeIsSentImmediatelyEvenWhenSenderIsNotFlushed() throws Exception {
        // Given
        sender.enableAllLevels();

        // When
        sender.sendProbe(EncryptionLevel.App);
        sender.doLoopIteration();

        // Then
        verify(socketManager).send(any(ByteBuffer.class), any(InetSocketAddress.class));
    }

    @Test
    @Timeout(value = 500, unit = TimeUnit.MILLISECONDS)
    void probeWithDataIsSentImmediatelyEvenWhenSenderIsNotFlushed() throws Exception {
        // Given
        sender.enableAllLevels();

        // When
        sender.sendProbe(List.of(new CryptoFrame(Version.getDefault(), new byte[368])), EncryptionLevel.App);
        sender.doLoopIteration();

        // Then
        verify(socketManager).send(any(ByteBuffer.class), any(InetSocketAddress.class));
    }

    @Test
    void whenInitialKeysAreDiscardedSendShouldNotThrowButJustIgnoreThePacket() throws Exception {
        // Given
        when(connectionSecrets.getOwnAead(EncryptionLevel.Initial)).thenThrow(new MissingKeysException(EncryptionLevel.Initial, true));

        // When
        InitialPacket initialPacket = new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, new AckFrame(0));
        initialPacket.setPacketNumber(1);
        sender.send(mutableListOf(new SendItem(initialPacket, getArbitraryLocalAddress())));

        // Then
        verify(socketManager, never()).send(any(ByteBuffer.class), any(InetSocketAddress.class));
    }

    private <T> List<T> mutableListOf(T item) {
        ArrayList<T> list = new ArrayList<>();
        list.add(item);
        return list;
    }
}
