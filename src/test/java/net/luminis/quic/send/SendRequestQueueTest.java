/*
 * Copyright © 2020, 2021 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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
package net.luminis.quic.send;

import net.luminis.quic.Version;
import net.luminis.quic.frame.CryptoFrame;
import net.luminis.quic.frame.QuicFrame;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SendRequestQueueTest {

    @Test
    void whenSecondAckHasMoreDelayFirstDelayWillBeUsed() throws Exception {
        SendRequestQueue sendRequestQueue = new SendRequestQueue();

        sendRequestQueue.addAckRequest(100);
        Instant start = Instant.now();
        sendRequestQueue.addAckRequest(200);

        Instant next = sendRequestQueue.nextDelayedSend();

        assertThat(Duration.between(start, next).toMillis()).isLessThan(100);
    }

    @Test
    void whenSecondAckHasShorterDelaySecondDelayWillBeUsed() throws Exception {
        SendRequestQueue sendRequestQueue = new SendRequestQueue();

        sendRequestQueue.addAckRequest(200);
        sendRequestQueue.addAckRequest(100);
        Instant start = Instant.now();

        Instant next = sendRequestQueue.nextDelayedSend();

        assertThat(Duration.between(start, next).toMillis()).isLessThan(100);
    }

    @Test
    void whenSecondAckHasNoDelaySecondDelayWillBeUsed() throws Exception {
        SendRequestQueue sendRequestQueue = new SendRequestQueue();

        sendRequestQueue.addAckRequest(200);
        sendRequestQueue.addAckRequest(0);
        Instant start = Instant.now();

        Instant next = sendRequestQueue.nextDelayedSend();

        assertThat(Duration.between(start, next).toMillis()).isLessThanOrEqualTo(0);
    }

    @Test
    void whenProbeIsVanishedDueToClearDoReturnProbe() throws Exception {
        // Given
        SendRequestQueue sendRequestQueue = new SendRequestQueue();
        sendRequestQueue.addProbeRequest(List.of(new CryptoFrame(Version.getDefault(), new byte[100])));

        boolean hasProbe = sendRequestQueue.hasProbeWithData();   // client is checking for probe
        assertThat(hasProbe).isTrue();

        // When
        sendRequestQueue.clear();   // But concurrent call to clear removes it

        // Then
        List<QuicFrame> probe = sendRequestQueue.getProbe();
        assertThat(probe)
                .isNotNull()
                .isNotEmpty();
    }
}