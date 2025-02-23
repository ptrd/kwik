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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;


class FixedAddressReceiverTest {

    private FixedAddressReceiver receiver;
    private DatagramSocket receiverSocket;
    private InetSocketAddress receiverAddress;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        receiverSocket = new DatagramSocket();
        receiverAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), receiverSocket.getLocalPort());
        receiver = new FixedAddressReceiver(receiverSocket, mock(Logger.class), throwable -> {});
        receiver.start();
    }

    @AfterEach
    void disposeObjectUnderTest() {
        receiver.shutdown();
    }

    @Test
    void canReceiveDatagram() throws Exception {
        // Given
        DatagramSocket sender = new DatagramSocket();
        DatagramPacket packet = new DatagramPacket(new byte[56], 56, receiverAddress);

        // When
        sender.send(packet);

        // Then
        RawPacket actual = receiver.get(1);
        assertThat(actual).isNotNull();
        assertThat(actual.getData().limit()).isEqualTo(56);
    }
}