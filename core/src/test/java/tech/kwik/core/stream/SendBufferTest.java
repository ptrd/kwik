/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.core.stream;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SendBufferTest {

    @Test
    void clearShouldWakeUpBlockedWriter() throws Exception {
        // Given a full buffer and a writer blocked on it
        int bufferSize = 100;
        SendBuffer sendBuffer = new SendBuffer(bufferSize);
        sendBuffer.write(new byte[bufferSize], 0, bufferSize);

        CountDownLatch writeCompleted = new CountDownLatch(1);
        Thread writer = new Thread(() -> {
            try {
                sendBuffer.write(new byte[10], 0, 10);
                writeCompleted.countDown();
            }
            catch (Exception e) {
                // Test will fail because latch is not counted down.
            }
        });
        writer.start();
        Thread.sleep(10);
        assertThat(writeCompleted.getCount()).isEqualTo(1);  // Writer is blocked

        // When
        sendBuffer.clear();

        // Then
        assertThat(writeCompleted.await(1, TimeUnit.SECONDS)).isTrue();
    }

    @Test
    void closeShouldFailWriteThatIsWaitingForBufferSpace() throws Exception {
        // Given a full buffer and a writer blocked on it
        int bufferSize = 100;
        SendBuffer sendBuffer = new SendBuffer(bufferSize);
        sendBuffer.write(new byte[bufferSize], 0, bufferSize);

        AtomicReference<Exception> thrownException = new AtomicReference<>();
        Thread writer = new Thread(() -> {
            try {
                sendBuffer.write(new byte[10], 0, 10);
            }
            catch (Exception e) {
                thrownException.set(e);
            }
        });
        writer.start();
        waitUntilWaiting(writer);

        // When
        sendBuffer.close();

        // Then
        writer.join(1000);
        boolean writerStillBlocked = writer.isAlive();
        writer.interrupt();
        assertThat(writerStillBlocked).isFalse();
        assertThat(thrownException.get()).isInstanceOf(IOException.class);
        assertThat(sendBuffer.getAvailableBytes()).isEqualTo(bufferSize);
    }

    @Test
    void writeAfterCloseShouldFail() throws Exception {
        // Given
        SendBuffer sendBuffer = new SendBuffer(100);
        sendBuffer.write(new byte[10], 0, 10);

        // When
        sendBuffer.close();

        // Then
        assertThatThrownBy(() -> sendBuffer.write(new byte[10], 0, 10))
                .isInstanceOf(IOException.class);
        assertThat(sendBuffer.getAvailableBytes()).isEqualTo(10);
    }

    @Test
    void whenWriterIsInterruptedBeforeItBlocksWriteShouldFail() throws Exception {
        // Given a full buffer
        int bufferSize = 100;
        SendBuffer sendBuffer = new SendBuffer(bufferSize);
        sendBuffer.write(new byte[bufferSize], 0, bufferSize);

        // When the blocked writer is interrupted before the writer has started to wait for buffer space
        sendBuffer.interruptBlockedWriter();

        AtomicReference<Exception> thrownException = new AtomicReference<>();
        Thread writer = new Thread(() -> {
            try {
                sendBuffer.write(new byte[10], 0, 10);
            }
            catch (Exception e) {
                thrownException.set(e);
            }
        });
        writer.start();

        // Then
        writer.join(1000);
        boolean writerStillBlocked = writer.isAlive();
        writer.interrupt();
        assertThat(writerStillBlocked).isFalse();
        assertThat(thrownException.get()).isInstanceOf(InterruptedException.class);
    }

    private void waitUntilWaiting(Thread thread) throws InterruptedException {
        Instant deadline = Instant.now().plusSeconds(1);
        while (thread.getState() != Thread.State.WAITING && Instant.now().isBefore(deadline)) {
            Thread.sleep(1);
        }
        assertThat(thread.getState()).isEqualTo(Thread.State.WAITING);
    }
}
