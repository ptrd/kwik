/*
 * Copyright © 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.server.impl;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketFilter;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.ServerRolePacketParser;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

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
    void testIncomingPacketsShouldBeParsed() throws Exception {
        // Given
        PacketMetaData metaData = new PacketMetaData(Instant.now(), new InetSocketAddress(54221), 10);
        serverConnectionThread = new ServerConnectionThread(serverConnection, List.of(), ByteBuffer.allocate(0), metaData, mock(Logger.class));

        // When
        serverConnectionThread.parsePackets(10, Instant.now(), ByteBuffer.allocate(71), new InetSocketAddress(54221));
        Thread.sleep(10);

        // Then
        verify(parser).parseAndProcessPackets(argThat(buffer -> buffer.remaining() == 71), any(PacketMetaData.class));
    }

    @Test
    void testRemainingDatagramDataShouldBeParsed() throws Exception {
        // Given
        PacketMetaData metaData = new PacketMetaData(Instant.now(), new InetSocketAddress(54221), 10);
        ByteBuffer remainingData = ByteBuffer.allocate(1173);
        remainingData.position(1100);

        // When
        serverConnectionThread = new ServerConnectionThread(serverConnection, List.of(), remainingData, metaData, mock(Logger.class));
        Thread.sleep(10);

        // Then
        verify(parser).parseAndProcessPackets(argThat(buffer -> buffer.remaining() == 73), any(PacketMetaData.class));
    }

    @Test
    void testRemainingDatagramDataShouldNotIncreaseAntiAmplificationLimit() throws InterruptedException {
        // Given
        AtomicInteger antiAmplificationLimit = new AtomicInteger(0);
        stubAntiAmplificationLimitWith(antiAmplificationLimit);

        PacketMetaData metaData = new PacketMetaData(Instant.now(), new InetSocketAddress(54221), 10);
        ByteBuffer remainingData = ByteBuffer.allocate(1173);
        remainingData.position(1100);

        // When
        serverConnectionThread = new ServerConnectionThread(serverConnection, mock(List.class), remainingData, metaData, mock(Logger.class));
        Thread.sleep(10);

        // Then
        assertThat(antiAmplificationLimit.get()).isZero();
    }

    private void stubAntiAmplificationLimitWith(AtomicInteger antiAmplificationLimit) {
        doAnswer(invocation -> {
            antiAmplificationLimit.addAndGet(invocation.getArgument(0));
            return null;
        }).when(serverConnection).increaseAntiAmplificationLimit(anyInt());
    }
}