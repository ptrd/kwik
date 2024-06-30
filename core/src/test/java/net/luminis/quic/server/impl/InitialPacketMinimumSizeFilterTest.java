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
 */package net.luminis.quic.server.impl;

import net.luminis.quic.impl.TestUtils;
import net.luminis.quic.impl.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.DatagramFilter;
import net.luminis.quic.packet.PacketMetaData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;


class InitialPacketMinimumSizeFilterTest {

    private InitialPacketMinimumSizeFilter filter;
    private DatagramFilter sink;
    private PacketMetaData metaData;

    @BeforeEach
    void setUp() {
        sink = mock(DatagramFilter.class);
        filter = new InitialPacketMinimumSizeFilter(mock(Logger.class), sink);
        metaData = mock(PacketMetaData.class);
    }

    @Test
    void initialPacketCarriedInDatagramSmallerThan1200BytesShouldBeDropped() throws Exception {
        // Given
        byte[] initialPacketBytes = TestUtils.createValidInitialNoPadding(Version.getDefault());

        // When
        filter.processDatagram(ByteBuffer.wrap(initialPacketBytes), metaData);

        // Then
        verify(sink, never()).processDatagram(any(ByteBuffer.class), any(PacketMetaData.class));
    }

    @Test
    void initialPacketWithPaddingInDatagramShouldBeAccepted() throws Exception {
        // Given
        byte[] initialPacketBytes = TestUtils.createValidInitialNoPadding(Version.getDefault());
        ByteBuffer buffer = ByteBuffer.allocate(1200);
        buffer.put(initialPacketBytes);
        buffer.position(0);

        // When
        filter.processDatagram(buffer, metaData);

        // Then
        verify(sink).processDatagram(any(ByteBuffer.class), any(PacketMetaData.class));
    }

    @Test
    void nonInitialPacketShouldPassFilter() {
        // Given
        byte handshakePacketFlags = (byte) 0b1110_0000;
        byte[] packetBytes = new byte[] { handshakePacketFlags, 0, 0, 0, 0 };
        filter.processDatagram(ByteBuffer.wrap(packetBytes), metaData);

        verify(sink).processDatagram(any(ByteBuffer.class), any(PacketMetaData.class));
    }

    @Test
    void oneRttPacketShouldPassFilter() {
        // Given
        byte oneRttPacketFlags = (byte) 0b0100_0000;
        byte[] packetBytes = new byte[] { oneRttPacketFlags, 0, 0, 0, 0 };
        filter.processDatagram(ByteBuffer.wrap(packetBytes), metaData);

        verify(sink).processDatagram(any(ByteBuffer.class), any(PacketMetaData.class));
    }
}
