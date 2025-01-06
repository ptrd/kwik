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
package tech.kwik.core.receive;

import tech.kwik.core.log.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;


class ReceiverTest {

    static final private int GET_TIMEOUT = 1;
    static private DatagramSocket socket;

    @BeforeEach
    void initSocket() throws SocketException {
        socket = new DatagramSocket();
    }

    @AfterEach
    void closeSocket() {
        socket.close();
    }

    @Test
    void withoutFilterAnyPacketShouldBeReceived() throws Exception {
        // Given
        Receiver receiver = createReceiver(null);

        // When
        sendFromPort(new byte[] { 0x73 }, 1234);

        // Then
        RawPacket rawPacket = receiver.get(GET_TIMEOUT);
        assertThat(rawPacket).isNotNull();
        assertThat(rawPacket.getData().get()).isEqualTo((byte) 0x73);
        assertThat(rawPacket.getPort()).isEqualTo(1234);
    }

    @Test
    void packetNotPassingFilterShouldBeDropped() throws Exception {
        // Given
        Predicate<DatagramPacket> filter = packet -> packet.getPort() == 9999;
        Receiver receiver = createReceiver(filter);

        // When
        sendFromPort(new byte[] { 0x73 }, 1234);

        // Then
        RawPacket rawPacket = receiver.get(GET_TIMEOUT);
        assertThat(rawPacket).isNull();
    }

    private Receiver createReceiver(Predicate<DatagramPacket> filter) {
        Receiver receiver;
        if (filter == null) {
            receiver = new Receiver(socket, mock(Logger.class), t -> {});
        } else {
            receiver = new Receiver(socket, mock(Logger.class), t -> {}, filter);
        }
        receiver.start();
        return receiver;
    }

    private void sendFromPort(byte[] data, int port) throws Exception {
        DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getLoopbackAddress(), socket.getLocalPort());

        DatagramSocket senderSocket = new DatagramSocket(port);
        senderSocket.send(packet);
        senderSocket.close();
    }
}