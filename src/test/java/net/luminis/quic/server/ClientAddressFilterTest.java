/*
 * Copyright © 2023 Peter Doornbosch
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
package net.luminis.quic.server;

import net.luminis.quic.log.Logger;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.*;

class ClientAddressFilterTest {

    @Test
    void filterAllowsPacketsFromInitialClientAddress() {
        // Given
        ServerConnectionProxy connection = mock(ServerConnectionProxy.class);
        InetSocketAddress initialClientAddress = new InetSocketAddress("www.example.com", 5839);
        ClientAddressFilter filter = new ClientAddressFilter(connection, initialClientAddress, mock(Logger.class));

        // When
        filter.parsePackets(1, Instant.now(), ByteBuffer.allocate(50), initialClientAddress);

        // Then
        verify(connection).parsePackets(anyInt(), any(Instant.class), any(ByteBuffer.class), any(InetSocketAddress.class));
    }

    @Test
    void filterDropsPacketsNotFromInitialClientAddress() {
        // Given
        ServerConnectionProxy connection = mock(ServerConnectionProxy.class);
        InetSocketAddress initialClientAddress = new InetSocketAddress("www.example.com", 5839);
        ClientAddressFilter filter = new ClientAddressFilter(connection, initialClientAddress, mock(Logger.class));

        // When
        InetSocketAddress otherAddress = new InetSocketAddress("www.example.com", 5840);
        filter.parsePackets(1, Instant.now(), ByteBuffer.allocate(50), otherAddress);

        // Then
        verify(connection, never()).parsePackets(anyInt(), any(Instant.class), any(ByteBuffer.class), any(InetSocketAddress.class));
    }
}