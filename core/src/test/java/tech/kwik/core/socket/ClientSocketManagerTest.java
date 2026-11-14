/*
 * Copyright © 2023, 2024, 2025, 2026 Peter Doornbosch
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
import org.mockito.ArgumentCaptor;
import tech.kwik.core.DatagramSocketFactory;
import tech.kwik.core.receive.MultipleAddressReceiver;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

    @Test
    void alternateSocketFromFactoryIsUsedToSendToAlternateAddress() throws IOException {
        // Given
        DatagramSocket initialSocket = mock(DatagramSocket.class);
        when(initialSocket.getLocalPort()).thenReturn(1000);
        DatagramSocket alternateSocket = mock(DatagramSocket.class);
        when(alternateSocket.getLocalPort()).thenReturn(2000);

        DatagramSocketFactory socketFactory = new DatagramSocketFactory() {
            @Override
            public DatagramSocket createSocket(InetAddress destination) {
                return initialSocket;
            }
            @Override
            public DatagramSocket createSocket(InetAddress destination, Integer localPort) {
                return alternateSocket;
            }
        };
        var serverAddress = new InetSocketAddress("example.com", 4433);
        var socketMgr = new ClientSocketManager(serverAddress, mock(MultipleAddressReceiver.class), socketFactory);
        InetSocketAddress alternateAddress = socketMgr.addLocalAddress(null);

        // When
        socketMgr.send(ByteBuffer.allocate(100), alternateAddress);

        // Then
        ArgumentCaptor<DatagramPacket> datagram = ArgumentCaptor.forClass(DatagramPacket.class);
        verify(alternateSocket).send(datagram.capture());
        verify(initialSocket, never()).send(any());
        assertThat(datagram.getValue().getAddress()).isEqualTo(serverAddress.getAddress());
        assertThat(datagram.getValue().getPort()).isEqualTo(serverAddress.getPort());
    }

    @Test
    void newSocketFromFactoryIsUsedToSendAfterChangingLocalAddress() throws IOException {
        // Given
        DatagramSocket initialSocket = mock(DatagramSocket.class);
        when(initialSocket.getLocalPort()).thenReturn(1000);
        DatagramSocket newSocket = mock(DatagramSocket.class);
        when(newSocket.getLocalPort()).thenReturn(2000);

        DatagramSocketFactory socketFactory = new DatagramSocketFactory() {
            @Override
            public DatagramSocket createSocket(InetAddress destination) {
                return initialSocket;
            }
            @Override
            public DatagramSocket createSocket(InetAddress destination, Integer localPort) {
                return newSocket;
            }
        };
        var serverAddress = new InetSocketAddress("example.com", 4433);
        var socketMgr = new ClientSocketManager(serverAddress, mock(MultipleAddressReceiver.class), socketFactory);
        InetSocketAddress newAddress = socketMgr.changeLocalAddress(null);

        // When
        socketMgr.send(ByteBuffer.allocate(100), newAddress);

        // Then
        verify(newSocket).send(any());
        verify(initialSocket, never()).send(any());
    }

    // region address change
    @Test
    void previousAddressCanStillBeUsedAfterChangingLocalAddress() throws IOException {
        // Given
        DatagramSocket initialSocket = mockSocket(1000);
        DatagramSocket newSocket = mockSocket(2000);
        var socketMgr = new ClientSocketManager(new InetSocketAddress("example.com", 4433), mock(MultipleAddressReceiver.class), socketFactory(initialSocket, newSocket));
        InetSocketAddress initialAddress = socketMgr.getClientAddress();

        // When
        socketMgr.changeLocalAddress(null);
        socketMgr.send(ByteBuffer.allocate(100), initialAddress);

        // Then
        verify(initialSocket).send(any());
        verify(newSocket, never()).send(any());
    }

    @Test
    void changingToAlternateAddressMakesItTheCurrentAddress() throws IOException {
        // Given
        DatagramSocket alternateSocket = mockSocket(2000);
        var socketMgr = new ClientSocketManager(new InetSocketAddress("example.com", 4433), mock(MultipleAddressReceiver.class), socketFactory(mockSocket(1000), alternateSocket));
        InetSocketAddress alternateAddress = socketMgr.addLocalAddress(null);

        // When
        InetSocketAddress newAddress = socketMgr.changeLocalAddress(alternateAddress.getPort());

        // Then
        assertThat(newAddress).isEqualTo(alternateAddress);
        assertThat(socketMgr.getClientAddress()).isEqualTo(alternateAddress);
        assertThat(socketMgr.getAlternateClientAddress()).isNull();
        assertThat(socketMgr.getSocket()).isSameAs(alternateSocket);
    }

    @Test
    void removingAddressRemovesSocketFromReceiver() throws IOException {
        // Given
        DatagramSocket alternateSocket = mockSocket(2000);
        MultipleAddressReceiver receiver = mock(MultipleAddressReceiver.class);
        var socketMgr = new ClientSocketManager(new InetSocketAddress("example.com", 4433), receiver, socketFactory(mockSocket(1000), alternateSocket));
        InetSocketAddress alternateAddress = socketMgr.addLocalAddress(null);

        // When
        socketMgr.removeLocalAddress(alternateAddress);

        // Then
        verify(receiver).removeSocket(alternateSocket);
        assertThat(socketMgr.getAlternateClientAddress()).isNull();
    }

    @Test
    void datagramForRemovedAddressIsDropped() throws IOException {
        // Given
        DatagramSocket initialSocket = mockSocket(1000);
        DatagramSocket alternateSocket = mockSocket(2000);
        var socketMgr = new ClientSocketManager(new InetSocketAddress("example.com", 4433), mock(MultipleAddressReceiver.class), socketFactory(initialSocket, alternateSocket));
        InetSocketAddress alternateAddress = socketMgr.addLocalAddress(null);
        socketMgr.removeLocalAddress(alternateAddress);

        // When
        Instant timeSent = socketMgr.send(ByteBuffer.allocate(100), alternateAddress);

        // Then
        assertThat(timeSent).isNotNull();
        verify(initialSocket, never()).send(any());
        verify(alternateSocket, never()).send(any());
    }

    @Test
    void datagramIsDroppedWhenSocketIsRemovedWhileSending() throws IOException {
        // Given
        DatagramSocket alternateSocket = mockSocket(2000);
        var socketMgr = new ClientSocketManager(new InetSocketAddress("example.com", 4433), mock(MultipleAddressReceiver.class), socketFactory(mockSocket(1000), alternateSocket));
        InetSocketAddress alternateAddress = socketMgr.addLocalAddress(null);
        doAnswer(invocation -> {
            socketMgr.removeLocalAddress(alternateAddress);
            when(alternateSocket.isClosed()).thenReturn(true);
            throw new SocketException("Socket is closed");
        }).when(alternateSocket).send(any());

        // When
        Instant timeSent = socketMgr.send(ByteBuffer.allocate(100), alternateAddress);

        // Then
        assertThat(timeSent).isNotNull();
    }

    @Test
    void socketExceptionOnRegisteredSocketIsNotSuppressed() throws IOException {
        // Given
        DatagramSocket initialSocket = mockSocket(1000);
        var socketMgr = new ClientSocketManager(new InetSocketAddress("example.com", 4433), mock(MultipleAddressReceiver.class), socketFactory(initialSocket, mockSocket(2000)));
        doThrow(new SocketException("Network is unreachable")).when(initialSocket).send(any());

        // When / Then
        assertThatThrownBy(() -> socketMgr.send(ByteBuffer.allocate(100), socketMgr.getClientAddress()))
                .isInstanceOf(SocketException.class);
    }

    @Test
    void currentAddressCannotBeRemoved() throws IOException {
        // Given
        var socketMgr = new ClientSocketManager(new InetSocketAddress("example.com", 4433), mock(MultipleAddressReceiver.class), socketFactory(mockSocket(1000), mockSocket(2000)));

        // When / Then
        assertThatThrownBy(() -> socketMgr.removeLocalAddress(socketMgr.getClientAddress()))
                .isInstanceOf(IllegalArgumentException.class);
    }
    // endregion

    private static DatagramSocket mockSocket(int localPort) {
        DatagramSocket socket = mock(DatagramSocket.class);
        when(socket.getLocalPort()).thenReturn(localPort);
        return socket;
    }

    private static DatagramSocketFactory socketFactory(DatagramSocket initialSocket, DatagramSocket otherSocket) {
        return new DatagramSocketFactory() {
            @Override
            public DatagramSocket createSocket(InetAddress destination) {
                return initialSocket;
            }
            @Override
            public DatagramSocket createSocket(InetAddress destination, Integer localPort) {
                return otherSocket;
            }
        };
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