/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.send;

import tech.kwik.core.frame.CryptoFrame;
import tech.kwik.core.frame.DatagramFrame;
import tech.kwik.core.frame.PathResponseFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.Version;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SendRequestQueueTest {

    private SendRequestQueue sendRequestQueue;

    @BeforeEach
    void setUp() {
        sendRequestQueue = new SendRequestQueue(null);
    }

    //region next
    @Test
    void nextReturnsFirstItemSmallerThanGivenFrameLength() throws Exception {
        // Given
        sendRequestQueue.addRequest(new CryptoFrame(Version.getDefault(), 0, new byte[1000]), f -> {});
        sendRequestQueue.addRequest(new CryptoFrame(Version.getDefault(), 0, new byte[1000]), f -> {});
        sendRequestQueue.addRequest(new CryptoFrame(Version.getDefault(), 0, new byte[67]), f -> {});
        sendRequestQueue.addRequest(new CryptoFrame(Version.getDefault(), 0, new byte[1000]), f -> {});

        // When
        Optional<SendRequest> sendRequest = sendRequestQueue.next(100);
        // Then
        assertThat(sendRequest).isPresent();
        assertThat(sendRequest.get().getEstimatedSize()).isLessThanOrEqualTo(100);
    }

    @Test
    void whenNoFrameIsSmallerThanGivenFrameLengthNextShouldReturnNothing() {
        // Given
        sendRequestQueue.addRequest(new CryptoFrame(Version.getDefault(), 0, new byte[1000]), f -> {});
        sendRequestQueue.addRequest(new CryptoFrame(Version.getDefault(), 0, new byte[572]), f -> {});
        sendRequestQueue.addRequest(new CryptoFrame(Version.getDefault(), 0, new byte[167]), f -> {});
        sendRequestQueue.addRequest(new CryptoFrame(Version.getDefault(), 0, new byte[1000]), f -> {});

        // When
        Optional<SendRequest> sendRequest = sendRequestQueue.next(100);
        // Then
        assertThat(sendRequest).isNotPresent();
    }
    //endregion

    //region ack delay
    @Test
    void whenSecondAckHasMoreDelayFirstDelayWillBeUsed() throws Exception {
        sendRequestQueue.addAckRequest(100);
        Instant start = Instant.now();
        sendRequestQueue.addAckRequest(200);

        Instant next = sendRequestQueue.nextDelayedSend();

        assertThat(Duration.between(start, next).toMillis()).isLessThanOrEqualTo(100);
    }

    @Test
    void whenSecondAckHasShorterDelaySecondDelayWillBeUsed() throws Exception {
        sendRequestQueue.addAckRequest(200);
        sendRequestQueue.addAckRequest(100);
        Instant start = Instant.now();

        Instant next = sendRequestQueue.nextDelayedSend();

        assertThat(Duration.between(start, next).toMillis()).isLessThanOrEqualTo(100);
    }

    @Test
    void whenSecondAckHasNoDelaySecondDelayWillBeUsed() throws Exception {
        sendRequestQueue.addAckRequest(200);
        sendRequestQueue.addAckRequest(0);
        Instant start = Instant.now();

        Instant next = sendRequestQueue.nextDelayedSend();

        assertThat(Duration.between(start, next).toMillis()).isLessThanOrEqualTo(0);
    }
    //endregion

    //region probe
    @Test
    void whenProbeIsVanishedDueToClearDoReturnProbe() throws Exception {
        // Given
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

    @Test
    void testProbeWithData() throws Exception {
        sendRequestQueue.addProbeRequest();

        assertThat(sendRequestQueue.hasProbeWithData()).isFalse();
        assertThat(sendRequestQueue.hasProbe()).isTrue();
    }
    //endprobe

    //region frame type limit
    @Test
    void pathChallenge() throws Exception {
        // Given
        int maxNrOfPathResponseFrames = 256;
        for (int i = 0; i < maxNrOfPathResponseFrames; i++) {
            sendRequestQueue.addRequest(new PathResponseFrame(Version.getDefault(), new byte[8]), f -> {});
        }

        // When
        byte[] markerPattern = new byte[] { 0x0c, 0x0a, 0x0f, 0x0e, 0x0b, 0x0a, 0x0b, 0x0e };
        sendRequestQueue.addRequest(new PathResponseFrame(Version.getDefault(), markerPattern), f -> {});

        // Then
        Optional<SendRequest> queuedItem;
        SendRequest lastItem = null;
        int pollCount = 0;
        while ((queuedItem = sendRequestQueue.next(1024)).isPresent()) {
            pollCount++;
            lastItem = queuedItem.get();
        }

        assertThat(((PathResponseFrame) lastItem.getFrame(1024)).getData()).isNotEqualTo(markerPattern);
        assertThat(pollCount).isEqualTo(maxNrOfPathResponseFrames);
    }
    //endregion

    //region priority request
    @Test
    void priorityRequestShouldBeConsideredFirst() {
        sendRequestQueue.addRequest(new StreamFrame(8, new byte[1000], false), f -> {});
        sendRequestQueue.addPriorityRequest(new DatagramFrame(new byte[1000]), f -> {});

        assertThat(sendRequestQueue.next(1010).get().getFrame(1500)).isInstanceOf(DatagramFrame.class);
    }

    @Test
    void whenPriorityRequestDoesNotFitNextInQueueIsUsed() {
        sendRequestQueue.addRequest(new StreamFrame(8, new byte[1000], false), f -> {});
        sendRequestQueue.addPriorityRequest(new DatagramFrame(new byte[1010]), f -> {});

        assertThat(sendRequestQueue.next(1010).get().getFrame(1500)).isInstanceOf(StreamFrame.class);
    }
    //endregion
}