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

import net.luminis.quic.PnSpace;
import net.luminis.quic.QuicConnectionImpl;
import net.luminis.quic.Version;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.frame.DataBlockedFrame;
import net.luminis.quic.log.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.internal.util.reflection.FieldSetter;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class SenderV2ImplTest {

    private SenderV2Impl sender;
    private GlobalPacketAssembler packetAssembler;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        DatagramSocket socket = mock(DatagramSocket.class);
        InetSocketAddress peerAddress = new InetSocketAddress("example.com", 443);
        QuicConnectionImpl connection = mock(QuicConnectionImpl.class);
        when(connection.getDestinationConnectionId()).thenReturn(new byte[4]);
        when(connection.getSourceConnectionId()).thenReturn(new byte[4]);

        sender = new SenderV2Impl(Version.getDefault(), 1200, socket, peerAddress, connection, 100, mock(Logger.class));
        sender.start(mock(ConnectionSecrets.class));

        packetAssembler = mock(GlobalPacketAssembler.class);
        FieldSetter.setField(sender, sender.getClass().getDeclaredField("packetAssembler"), packetAssembler);
    }

    @Test
    void assemblePacketIsCalledBeforeAckDelayHasPassed() throws Exception {
        sender.sendAck(PnSpace.App, 50);
        Thread.sleep(40);
        verify(packetAssembler, never()).assemble(anyInt(), any(byte[].class), any(byte[].class));

        Thread.sleep(20);

        verify(packetAssembler, times(1)).assemble(anyInt(), any(byte[].class), any(byte[].class));
    }
}
