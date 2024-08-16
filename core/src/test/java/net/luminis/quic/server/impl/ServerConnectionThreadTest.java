/*
 * Copyright © 2024 Peter Doornbosch
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
package net.luminis.quic.server.impl;

import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.PacketFilter;
import net.luminis.quic.packet.PacketMetaData;
import net.luminis.quic.packet.ServerRolePacketParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ServerConnectionThreadTest {

    private ServerConnectionImpl serverConnection;
    private ServerRolePacketParser parser;
    private ServerConnectionThread serverConnectionThread;

    @BeforeEach
    void setUp() {
        serverConnection = mock(ServerConnectionImpl.class);
        when(serverConnection.getOriginalDestinationConnectionId()).thenReturn(new byte[0]);
        when(serverConnection.getPacketProcessorChain()).thenReturn(mock(PacketFilter.class));
        parser = mock(ServerRolePacketParser.class);
        when(serverConnection.createParser()).thenReturn(parser);
    }

    @AfterEach
    void shutdownThread() {
        if (serverConnectionThread != null) {
            serverConnectionThread.dispose();
        }
    }

    @Test
    void testIncomingPacketsShouldBeParsed() throws InterruptedException {
        // Given
        serverConnectionThread = new ServerConnectionThread(serverConnection, mock(InitialPacket.class), ByteBuffer.allocate(0), mock(PacketMetaData.class));

        // When
        serverConnectionThread.parsePackets(10, Instant.now(), ByteBuffer.allocate(71), null);
        Thread.sleep(10);

        // Then
        verify(parser).parseAndProcessPackets(argThat(buffer -> buffer.remaining() == 71), any(PacketMetaData.class));
    }

    @Test
    void testRemainingDatagramDataShouldBeParsed() throws InterruptedException {
        // Given
        ByteBuffer remainingData = ByteBuffer.allocate(1173);
        remainingData.position(1100);

        // When
        serverConnectionThread = new ServerConnectionThread(serverConnection, mock(InitialPacket.class), remainingData, mock(PacketMetaData.class));
        Thread.sleep(10);

        // Then
        verify(parser).parseAndProcessPackets(argThat(buffer -> buffer.remaining() == 73), any(PacketMetaData.class));
    }
}