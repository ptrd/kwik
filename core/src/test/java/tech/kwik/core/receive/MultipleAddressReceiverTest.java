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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.log.Logger;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;


class MultipleAddressReceiverTest {

    static final private int GET_TIMEOUT = 1;

    private MultipleAddressReceiver receiver;
    private DatagramSocket receiverSocket;
    private InetSocketAddress receiverAddress;
    private Logger logger;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        logger = mock(Logger.class);
        receiver = new MultipleAddressReceiver(logger, p -> true, throwable -> {});
        receiver.start();
        receiverSocket = new DatagramSocket();
        receiver.addSocket(receiverSocket);
        receiverAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), receiverSocket.getLocalPort());
    }

    @AfterEach
    void disposeObjectUnderTest() {
        receiver.shutdown();
    }

    @Test
    void canReceiveDatagram() throws Exception {
        // Given

        // When
        DatagramSocket sender = new DatagramSocket();
        DatagramPacket packet = new DatagramPacket(new byte[56], 56, receiverAddress);
        sender.send(packet);

        // Then
        RawPacket actual = receiver.get(1);
        assertThat(actual).isNotNull();
        assertThat(actual.getData().limit()).isEqualTo(56);
    }

    @Test
    void canReceiveOnAlternateAddressToo() throws Exception {
        // Given
        DatagramSocket extraReceiverSocket = new DatagramSocket();
        receiver.addSocket(extraReceiverSocket);
        InetSocketAddress newAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), extraReceiverSocket.getLocalPort());

        // When
        DatagramSocket sender = new DatagramSocket();
        DatagramPacket packet1 = new DatagramPacket(new byte[111], 111, receiverAddress);
        DatagramPacket packet2 = new DatagramPacket(new byte[222], 222, newAddress);
        sender.send(packet1);
        sender.send(packet2);

        // Then
        RawPacket actual1 = receiver.get(1);
        assertThat(actual1).isNotNull();
        RawPacket actual2 = receiver.get(1);
        assertThat(actual2).isNotNull();

        // Receive order can be different from send order! So check that both are received without assuming order.
        List<Integer> lengths = Stream.of(actual1, actual2).map(p -> p.getData().limit()).collect(Collectors.toList());
        assertThat(lengths).contains(111);
        assertThat(lengths).contains(222);
    }

    @Test
    void whenSocketIsClosedThreadTerminationDoesNotLogError() throws Exception {
        // Given
        DatagramSocket secondReceiverSocket = new DatagramSocket();
        receiver.addSocket(secondReceiverSocket);
        Thread.sleep(30);  // Give thread a chance to start

        // When
        receiver.removeSocket(secondReceiverSocket);

        // Then
        verify(logger, never()).error(anyString());
        verify(logger, never()).error(anyString(), any(Throwable.class));
    }

    @Test
    void withoutFilterAnyPacketShouldBeReceived() throws Exception {
        // Given

        // When
        sendFromPort(new byte[] { 0x73 }, 1234);

        // Then
        RawPacket rawPacket = receiver.get(GET_TIMEOUT);
        assertThat(rawPacket).isNotNull();
        assertThat(rawPacket.getData().get()).isEqualTo((byte) 0x73);
        assertThat(rawPacket.getPeerAddress().getPort()).isEqualTo(1234);
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
        receiver = new MultipleAddressReceiver(logger, filter, throwable -> {});
        receiver.start();
        receiver.addSocket(receiverSocket);
        return receiver;
    }

    private void sendFromPort(byte[] data, int port) throws Exception {
        DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getLoopbackAddress(), receiverSocket.getLocalPort());

        DatagramSocket senderSocket = new DatagramSocket(port);
        senderSocket.send(packet);
        senderSocket.close();
    }
}
