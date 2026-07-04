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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

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
}
