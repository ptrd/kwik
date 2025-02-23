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
package tech.kwik.core.socket;

import org.junit.jupiter.api.Test;
import tech.kwik.core.DatagramSocketFactory;
import tech.kwik.core.receive.MultipleAddressReceiver;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class ClientSocketManagerTest {

    @Test
    void withoutDatagramSocketFactoryDefaultDatagramSocketShouldBeCreated() throws SocketException {
        // Given
        var socketMgr = new ClientSocketManager(new InetSocketAddress("example.com", 4433), mock(MultipleAddressReceiver.class), null);

        // When
        DatagramSocket socket = socketMgr.getSocket();

        // Then
        assertThat(socket).isNotNull();
        assertThat(socket).isInstanceOf(DatagramSocket.class);
    }

    @Test
    void withDatagramSocketFactoryCustomSocketShouldBeCreated() throws SocketException {
        // Given
        var socketFactory = new CustomSocketFactory();
        var socketMgr = new ClientSocketManager(new InetSocketAddress("example.com", 4433), mock(MultipleAddressReceiver.class), socketFactory);

        // When
        DatagramSocket socket = socketMgr.getSocket();

        // Then
        assertThat(socket).isNotNull();
        assertThat(socket).isInstanceOf(CustomDatagramSocket.class);
    }

    static class CustomSocketFactory implements DatagramSocketFactory {
        @Override
        public DatagramSocket createSocket(InetAddress destination) throws SocketException {
            return new CustomDatagramSocket();
        }
    }

    static class CustomDatagramSocket extends DatagramSocket {
        public CustomDatagramSocket() throws SocketException {
        }
    }
}