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
package net.luminis.quic.send;

import net.luminis.quic.*;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.crypto.Keys;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.NullLogger;
import net.luminis.quic.packet.ShortHeaderPacket;
import net.luminis.quic.test.TestClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.internal.util.reflection.FieldReader;
import org.mockito.internal.util.reflection.FieldSetter;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class SenderImplTest extends AbstractSenderTest {

    private TestClock clock;
    private SenderImpl sender;
    private GlobalPacketAssembler packetAssembler;
    private DatagramSocket socket;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        clock = new TestClock();
        socket = mock(DatagramSocket.class);
        InetSocketAddress peerAddress = new InetSocketAddress("example.com", 443);
        QuicConnectionImpl connection = mock(QuicConnectionImpl.class);
        when(connection.getDestinationConnectionId()).thenReturn(new byte[4]);
        when(connection.getSourceConnectionId()).thenReturn(new byte[4]);
        when(connection.getIdleTimer()).thenReturn(new IdleTimer(connection, new NullLogger()));

        ConnectionSecrets connectionSecrets = mock(ConnectionSecrets.class);
        Keys keys = createKeys();
        when(connectionSecrets.getOwnSecrets(any(EncryptionLevel.class))).thenReturn(keys);

        sender = new SenderImpl(clock, Version.getDefault(), 1200, socket, peerAddress, connection, 100, new NullLogger());
        FieldSetter.setField(sender, sender.getClass().getDeclaredField("connectionSecrets"), connectionSecrets);
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
        sender.send(List.of(new SendItem(packet1)));
        packet1.setPacketNumber(11);
        packet2.setPacketNumber(12);
        sender.send(List.of(new SendItem(packet1), new SendItem(packet2)));

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
        verify(packetAssembler, atLeastOnce()).assemble(anyInt(), packetSizeCaptor.capture(), any(byte[].class), any(byte[].class));
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
        verify(socket, times(3)).send(any(DatagramPacket.class));
    }

    private void setupMockPacketAssember() throws NoSuchFieldException {
        packetAssembler = mock(GlobalPacketAssembler.class);
        when(packetAssembler.assemble(anyInt(), anyInt(), any(byte[].class), any(byte[].class))).thenReturn(List.of(new SendItem(new MockPacket(0, 1200, ""))));
        when(packetAssembler.nextDelayedSendTime()).thenReturn(Optional.empty());
        FieldSetter.setField(sender, sender.getClass().getDeclaredField("packetAssembler"), packetAssembler);
    }

}
