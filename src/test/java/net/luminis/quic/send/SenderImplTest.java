/*
 * Copyright © 2020 Peter Doornbosch
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
package net.luminis.quic.send;

import net.luminis.quic.*;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.crypto.Keys;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.NullLogger;
import net.luminis.quic.packet.ShortHeaderPacket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.internal.util.reflection.FieldReader;
import org.mockito.internal.util.reflection.FieldSetter;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class SenderImplTest extends AbstractSenderTest {

    private SenderImpl sender;
    private GlobalPacketAssembler packetAssembler;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        DatagramSocket socket = mock(DatagramSocket.class);
        InetSocketAddress peerAddress = new InetSocketAddress("example.com", 443);
        QuicConnectionImpl connection = mock(QuicConnectionImpl.class);
        when(connection.getDestinationConnectionId()).thenReturn(new byte[4]);
        when(connection.getSourceConnectionId()).thenReturn(new byte[4]);
        when(connection.getIdleTimer()).thenReturn(new IdleTimer(connection, new NullLogger()));

        ConnectionSecrets connectionSecrets = mock(ConnectionSecrets.class);
        Keys keys = createKeys();
        when(connectionSecrets.getOwnSecrets(any(EncryptionLevel.class))).thenReturn(keys);

        sender = new SenderImpl(Version.getDefault(), 1200, socket, peerAddress, connection, 100, new NullLogger());
        sender.start(connectionSecrets);

        packetAssembler = mock(GlobalPacketAssembler.class);
        FieldSetter.setField(sender, sender.getClass().getDeclaredField("packetAssembler"), packetAssembler);
    }

    @Test
    void assemblePacketIsCalledBeforeAckDelayHasPassed() throws Exception {
        sender.sendAck(PnSpace.App, 50);
        sender.packetProcessed(false);

        Thread.sleep(5);
        clearInvocations(packetAssembler);  // PacketProcessed will check to see if anything must be sent

        Thread.sleep(30);
        verify(packetAssembler, never()).assemble(anyInt(), any(byte[].class), any(byte[].class));

        Thread.sleep(20);
        verify(packetAssembler, atLeastOnce()).assemble(anyInt(), any(byte[].class), any(byte[].class));
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
    void addingProbeToDiscardedSpaceMovesItToNext() throws Exception {
        // Given
        SendRequestQueue[] senderQueues = (SendRequestQueue[]) new FieldReader(sender, sender.getClass().getDeclaredField("sendRequestQueue")).read();

        sender.discard(PnSpace.Initial, "test");

        // When
        sender.sendProbe(EncryptionLevel.Initial);

        // Then
        assertThat(senderQueues[EncryptionLevel.Initial.ordinal()].hasProbe()).isFalse();
        assertThat(senderQueues[EncryptionLevel.Handshake.ordinal()].hasProbe()).isTrue();
    }

    @Test
    void whenDiscardingSpacePendingProbeIsMovedToNextLevel() throws Exception {
        // Given
        SendRequestQueue[] senderQueues = (SendRequestQueue[]) new FieldReader(sender, sender.getClass().getDeclaredField("sendRequestQueue")).read();

        sender.sendProbe(EncryptionLevel.Initial);

        // When
        sender.discard(PnSpace.Initial, "test");

        // Then
        assertThat(senderQueues[EncryptionLevel.Initial.ordinal()].hasProbe()).isFalse();
        assertThat(senderQueues[EncryptionLevel.Handshake.ordinal()].hasProbe()).isTrue();
    }
}
