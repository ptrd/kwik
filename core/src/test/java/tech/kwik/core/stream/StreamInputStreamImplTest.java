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
package tech.kwik.core.stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.QuicConstants;
import tech.kwik.core.StreamClosedException;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.log.Logger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class StreamInputStreamImplTest {

    private StreamInputStreamImpl streamInputStream;
    private StreamManager streamManager;

    @BeforeEach
    void setUp() {
        streamManager = mock(StreamManager.class);

        QuicStreamImpl quicStream = new QuicStreamImpl(0, Role.Client, mock(QuicConnectionImpl.class), streamManager, mock(FlowControl.class));
        streamInputStream = new StreamInputStreamImpl(quicStream, 10_000L, mock(Logger.class));
    }

    @Test
    void whenFirstStreamFrameAddIncrEqualsUpToOffset() throws Exception {
        // When
        long incr = streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[876], false));

        // Then
        assertThat(incr).isEqualTo(876);
    }

    @Test
    void whenMultipleStreamFramesAddedIncrEqualsNetIncrement() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[700], false));

        // When
        long incr = streamInputStream.addDataFrom(new StreamFrame(0, 600, new byte[250], false));

        // Then
        assertThat(incr).isEqualTo(150);
    }

    @Test
    void whenMultipleStreamFramesAddedWithGapInBetweeIncrEqualsUpToOffsetDiff() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[500], false));

        // When
        long incr = streamInputStream.addDataFrom(new StreamFrame(0, 800, new byte[250], false));

        // Then
        assertThat(incr).isEqualTo(550);
    }

    // region terminateAt - frame validation

    @Test
    void terminateAtThrowsFrameEncodingErrorWhenReliableSizeExceedsFinalSize() {
        // When/Then: reliable size 900 exceeds final size 700
        assertThatThrownBy(() ->
                streamInputStream.terminateAt(0, 700, 900))
                .isInstanceOf(TransportError.class)
                .extracting(e -> ((TransportError) e).getErrorCode())
                .isEqualTo(QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR);
    }

    @Test
    void terminateAtThrowsFinalSizeErrorWhenFinalSizeBelowLargestOffsetReceived() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[900], false));

        // When/Then: final size 600 is below the largest offset received (900)
        assertThatThrownBy(() ->
                streamInputStream.terminateAt(0, 600, 400))
                .isInstanceOf(TransportError.class)
                .extracting(e -> ((TransportError) e).getErrorCode())
                .isEqualTo(QuicConstants.TransportErrorCode.FINAL_SIZE_ERROR);
    }

    @Test
    void terminateAtThrowsFinalSizeErrorWhenFinalSizeDiffersFromKnownFinalSize() throws Exception {
        // Given: a final stream frame established the final size as 900
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[900], true));

        // When/Then: the reset announces a different final size (1200)
        assertThatThrownBy(() ->
                streamInputStream.terminateAt(0, 1200, 400))
                .isInstanceOf(TransportError.class)
                .extracting(e -> ((TransportError) e).getErrorCode())
                .isEqualTo(QuicConstants.TransportErrorCode.FINAL_SIZE_ERROR);
    }

    // endregion

    // region terminateAt - return value

    @Test
    void terminateAtReturnsLargestOffsetIncrement() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[400], false));

        // When
        long increment = streamInputStream.terminateAt(0, 1000, 300);

        // Then: increment is final size (1000) minus largest offset received (400)
        assertThat(increment).isEqualTo(600);
    }

    @Test
    void terminateAtReturnsZeroIncrementWhenFinalSizeEqualsLargestOffsetReceived() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[900], false));

        // When: final size equals the largest offset received (900)
        long increment = streamInputStream.terminateAt(0, 900, 300);

        // Then
        assertThat(increment).isEqualTo(0);
    }

    // endregion

    // region terminateAt - data delivery and reset signalling

    @Test
    void terminateAtDeliversReliableDataBeforeSignallingReset() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[1000], false));

        // When
        streamInputStream.terminateAt(0, 1000, 700);

        // Then: the reliable data (up to 700) can still be read
        byte[] buffer = new byte[1000];
        int bytesRead = streamInputStream.read(buffer, 0, 1000);
        assertThat(bytesRead).isEqualTo(700);

        // And: once all reliable data is consumed, the stream is reset
        assertThatThrownBy(() -> streamInputStream.read(buffer, 0, 1000))
                .isInstanceOf(StreamClosedException.class);
    }

    @Test
    void terminateAtDoesNotSignalResetWhileReliableDataRemains() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[1000], false));
        streamInputStream.terminateAt(0, 1000, 700);

        // When: only part of the reliable data is read
        byte[] buffer = new byte[400];
        int firstRead = streamInputStream.read(buffer, 0, 400);

        // Then: no reset yet, remaining reliable data can still be read
        assertThat(firstRead).isEqualTo(400);
        int secondRead = streamInputStream.read(buffer, 0, 400);
        assertThat(secondRead).isEqualTo(300);

        // And: only after all reliable data is consumed the reset is signalled
        assertThatThrownBy(() -> streamInputStream.read(new byte[10], 0, 10))
                .isInstanceOf(StreamClosedException.class);
    }

    @Test
    void terminateAtDiscardsDataBeyondReliableSize() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[1000], false));

        // When
        streamInputStream.terminateAt(0, 1000, 700);

        // Then: data beyond the reliable size is never delivered
        byte[] buffer = new byte[1000];
        int bytesRead = streamInputStream.read(buffer, 0, 1000);
        assertThat(bytesRead).isEqualTo(700);
    }

    @Test
    void terminateAtSignalsResetImmediatelyWhenApplicationAlreadyReadPastReliableSize() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[1000], false));
        streamInputStream.read(new byte[800], 0, 800);  // read past the reliable size that follows

        // When
        streamInputStream.terminateAt(0, 1000, 700);

        // Then: the reset is signalled on the next read attempt
        assertThatThrownBy(() -> streamInputStream.read(new byte[10], 0, 10))
                .isInstanceOf(StreamClosedException.class);
    }

    // endregion

    // region terminateAt - flow control

    @Test
    void terminateAtReturnsFlowControlCreditsForUnreadDiscardedBytes() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[1000], false));

        // When
        streamInputStream.terminateAt(0, 1000, 700);

        // Then: the bytes between reliable size (700) and final size (1000) are returned to the connection flow control
        verify(streamManager).updateConnectionFlowControl(300L);
    }

    @Test
    void terminateAtDoesNotReturnFlowControlCreditsWhenReliableSizeEqualsFinalSize() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[900], false));

        // When: reliable size equals final size (900), so nothing is discarded
        streamInputStream.terminateAt(0, 900, 900);

        // Then: no flow control credits are returned
        verify(streamManager, never()).updateConnectionFlowControl(anyLong());
    }

    // endregion

    // region terminateAt - duplicate / retransmitted frames

    @Test
    void terminateAtAppliesLowerReliableSizeFromSecondFrame() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[1000], false));
        streamInputStream.terminateAt(0, 1000, 700);

        // When: a second RESET_STREAM_AT lowers the reliable size
        streamInputStream.terminateAt(0, 1000, 300);

        // Then: only the lower reliable size (300) is delivered to the application
        byte[] buffer = new byte[1000];
        int bytesRead = streamInputStream.read(buffer, 0, 1000);
        assertThat(bytesRead).isEqualTo(300);
    }

    @Test
    void terminateAtIgnoresHigherReliableSizeFromSecondFrame() throws Exception {
        // Given
        streamInputStream.addDataFrom(new StreamFrame(0, 0, new byte[1000], false));
        streamInputStream.terminateAt(0, 1000, 300);

        // When: a second RESET_STREAM_AT specifies a higher reliable size
        streamInputStream.terminateAt(0, 1000, 800);

        // Then: the lower reliable size (300) is kept
        byte[] buffer = new byte[1000];
        int bytesRead = streamInputStream.read(buffer, 0, 1000);
        assertThat(bytesRead).isEqualTo(300);
    }

    // endregion
}
