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
package tech.kwik.core.frame;

import org.junit.jupiter.api.Test;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.log.Logger;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;


class ResetStreamAtFrameTest {

    // region parse/serialize round-trip
    @Test
    void parseRoundTripPreservesAllFields() throws Exception {
        // Given
        var original = new ResetStreamAtFrame(8, 592, 65_000, 1_000);

        ByteBuffer buffer = ByteBuffer.allocate(100);
        original.serialize(buffer);
        buffer.flip();

        // When
        var parsed = new ResetStreamAtFrame().parse(buffer, mock(Logger.class));

        // Then
        assertThat(parsed.getStreamId()).isEqualTo(8);
        assertThat(parsed.getErrorCode()).isEqualTo(592);
        assertThat(parsed.getFinalSize()).isEqualTo(65_000);
        assertThat(parsed.getReliableSize()).isEqualTo(1_000);
    }

    @Test
    void getFrameLengthMatchesActualSerializedLength() {
        // Given
        var frame = new ResetStreamAtFrame(8, 592, 65_000, 1_000);

        // When
        ByteBuffer buffer = ByteBuffer.allocate(100);
        frame.serialize(buffer);
        buffer.flip();

        // Then
        assertThat(frame.getFrameLength()).isEqualTo(buffer.remaining());
    }

    @Test
    void getFrameLengthMatchesActualSerializedLengthWithLargeValues() {
        // Given — values that require multi-byte VLI encoding
        long largeErrorCode = 0x4000L;  // 2-byte VLI
        long largeFinalSize = 0x40000000L;  // 4-byte VLI
        long largeReliableSize = 0x3FFFFFFFL;  // 4-byte VLI
        var frame = new ResetStreamAtFrame(127, largeErrorCode, largeFinalSize, largeReliableSize);

        // When
        ByteBuffer buffer = ByteBuffer.allocate(100);
        frame.serialize(buffer);
        buffer.flip();

        // Then
        assertThat(frame.getFrameLength()).isEqualTo(buffer.remaining());
    }
    // endregion

    // region validation
    @Test
    void parseShouldThrowFrameEncodingErrorWhenReliableSizeExceedsFinalSize() {
        // Given — reliableSize > finalSize (invalid)
        var frame = new ResetStreamAtFrame(1, 0, 100, 200);  // reliableSize 200 > finalSize 100
        ByteBuffer buffer = ByteBuffer.allocate(100);
        frame.serialize(buffer);
        buffer.flip();

        // When / Then
        assertThatThrownBy(() -> new ResetStreamAtFrame().parse(buffer, mock(Logger.class)))
                .isInstanceOf(TransportError.class);
    }

    @Test
    void parseShouldAcceptReliableSizeEqualToFinalSize() throws Exception {
        // Given — reliableSize == finalSize (valid edge case)
        var original = new ResetStreamAtFrame(1, 0, 100, 100);
        ByteBuffer buffer = ByteBuffer.allocate(100);
        original.serialize(buffer);
        buffer.flip();

        // When
        var parsed = new ResetStreamAtFrame().parse(buffer, mock(Logger.class));

        // Then
        assertThat(parsed.getReliableSize()).isEqualTo(100);
        assertThat(parsed.getFinalSize()).isEqualTo(100);
    }

    @Test
    void parseShouldAcceptZeroReliableSize() throws Exception {
        // Given
        var original = new ResetStreamAtFrame(1, 0, 100, 0);
        ByteBuffer buffer = ByteBuffer.allocate(100);
        original.serialize(buffer);
        buffer.flip();

        // When
        var parsed = new ResetStreamAtFrame().parse(buffer, mock(Logger.class));

        // Then
        assertThat(parsed.getReliableSize()).isEqualTo(0);
    }
    // endregion

    // region frame type
    @Test
    void serializedFrameStartsWithTypeByte0x24() {
        // Given
        var frame = new ResetStreamAtFrame(1, 0, 100, 50);
        ByteBuffer buffer = ByteBuffer.allocate(100);

        // When
        frame.serialize(buffer);
        buffer.flip();

        // Then
        assertThat(buffer.get()).isEqualTo((byte) 0x24);
    }
    // endregion
}
