/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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

import org.junit.jupiter.api.Test;
import tech.kwik.core.log.Logger;

import java.net.DatagramSocket;
import java.net.PortUnreachableException;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

class AbstractReceiverTest {

    /**
     * A stray PortUnreachableException on the receive socket (e.g. an ICMP Port Unreachable response to an
     * unrelated, prior datagram) must not be treated as a fatal error: it should be logged and the receive loop
     * should keep running, instead of invoking the abort callback (which would tear down the whole connection,
     * or, on the server's main listening socket, the whole server).
     */
    @Test
    void portUnreachableExceptionDoesNotAbortReceiveLoop() throws Exception {
        // Given
        DatagramSocket socket = mock(DatagramSocket.class);
        AtomicInteger receiveCallCount = new AtomicInteger();
        CountDownLatch secondCallStarted = new CountDownLatch(1);
        doAnswer(invocation -> {
            if (receiveCallCount.getAndIncrement() == 0) {
                throw new PortUnreachableException("simulated ICMP port unreachable for a prior datagram");
            }
            secondCallStarted.countDown();
            try {
                Thread.sleep(2000);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            throw new SocketTimeoutException();
        }).when(socket).receive(any());

        List<Throwable> abortedWith = new CopyOnWriteArrayList<>();
        FixedAddressReceiver receiver = new FixedAddressReceiver(socket, mock(Logger.class), abortedWith::add);

        // When
        receiver.start();
        assertThat(secondCallStarted.await(2, TimeUnit.SECONDS)).isTrue();
        receiver.shutdown();

        // Then
        assertThat(receiveCallCount.get()).isGreaterThanOrEqualTo(2);
        assertThat(abortedWith).isEmpty();
    }
}
