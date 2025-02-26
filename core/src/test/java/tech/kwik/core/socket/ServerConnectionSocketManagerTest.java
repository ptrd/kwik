/*
 * Copyright © 2025 Peter Doornbosch
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
package tech.kwik.core.socket;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class ServerConnectionSocketManagerTest {

    private DatagramSocket serverSocket;
    private InetSocketAddress initialClientAddress;
    private ServerConnectionSocketManager socketManager;

    @BeforeEach
    void setup() {
        serverSocket = mock(DatagramSocket.class);
        initialClientAddress = new InetSocketAddress(Inet4Address.getLoopbackAddress(), 45981);
        socketManager = new ServerConnectionSocketManager(serverSocket, initialClientAddress);
    }

    @Test
    void defaultClientAddressShouldBeUsedAsDestinationAddressInDatagram() throws Exception {
        // When
        socketManager.send(ByteBuffer.allocate(79));

        // Then
        verify(serverSocket).send(argThat(p -> p.getSocketAddress().equals(initialClientAddress)));
    }

    @Test
    void explicitClientAddressShouldBeUsedAsDestinationAddressInDatagram() throws Exception {
        // When
        InetSocketAddress altAddress = new InetSocketAddress(Inet4Address.getByAddress(new byte[] { 73, 12, 68, 0}), 30287);
        socketManager.send(ByteBuffer.allocate(79), altAddress);

        // Then
        verify(serverSocket).send(argThat(p -> p.getSocketAddress().equals(altAddress)));
    }

    @Test
    void whenChangingClientAddressNewAddressShouldBeUsedAsSourceAddressInDatagram() throws Exception {
        // Given
        InetSocketAddress altAddress = new InetSocketAddress(Inet4Address.getByAddress(new byte[] { 73, 12, 68, 0}), 30287);
        socketManager.changeClientAddress(altAddress);

        // When
        socketManager.send(ByteBuffer.allocate(79));

        // Then
        verify(serverSocket).send(argThat(p -> p.getSocketAddress().equals(altAddress)));

    }
}