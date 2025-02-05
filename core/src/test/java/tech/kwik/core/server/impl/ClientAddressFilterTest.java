/*
 * Copyright © 2023, 2024, 2025 Peter Doornbosch
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

import org.junit.jupiter.api.Test;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.DatagramFilter;
import tech.kwik.core.packet.PacketMetaData;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class ClientAddressFilterTest {

    @Test
    void filterAllowsPacketsFromInitialClientAddress() throws Exception {
        // Given
        DatagramFilter sink = mock(DatagramFilter.class);
        InetSocketAddress initialClientAddress = new InetSocketAddress("www.example.com", 5839);
        ClientAddressFilter filter = new ClientAddressFilter(initialClientAddress, mock(Logger.class), sink);

        // When
        filter.processDatagram(ByteBuffer.allocate(50), new PacketMetaData(Instant.now(), initialClientAddress, 0));

        // Then
        verify(sink).processDatagram(any(ByteBuffer.class), any(PacketMetaData.class));
    }

    @Test
    void filterDropsPacketsNotFromInitialClientAddress() throws Exception {
        // Given
        DatagramFilter sink = mock(DatagramFilter.class);
        InetSocketAddress initialClientAddress = new InetSocketAddress("www.example.com", 5839);
        ClientAddressFilter filter = new ClientAddressFilter(initialClientAddress, mock(Logger.class), sink);

        // When
        InetSocketAddress otherAddress = new InetSocketAddress("www.example.com", 5840);
        filter.processDatagram(ByteBuffer.allocate(50), new PacketMetaData(Instant.now(), otherAddress, 0));

        // Then
        verify(sink, never()).processDatagram(any(ByteBuffer.class), any(PacketMetaData.class));
    }
}