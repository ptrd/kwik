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
package tech.kwik.h09.io;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LimitedInputStreamTest {

    // region read(byte[])
    @Test
    void readWithByteArrayShouldNotReadBeyondLimit() throws Exception {
        // Given
        InputStream input = new LimitedInputStream(new ByteArrayInputStream(new byte[100]), 10);

        // When
        int read = input.read(new byte[50]);

        // Then
        assertThat(read).isEqualTo(10);
    }

    @Test
    void readWithByteArrayShouldThrowWhenLimitIsReached() throws Exception {
        // Given
        InputStream input = new LimitedInputStream(new ByteArrayInputStream(new byte[100]), 10);
        input.read(new byte[50]);

        // When / Then
        assertThatThrownBy(() -> input.read(new byte[50]))
                .isInstanceOf(LimitExceededException.class);
    }

    @Test
    void readWithByteArrayShouldCountTowardsLimitOfOtherReadMethods() throws Exception {
        // Given
        InputStream input = new LimitedInputStream(new ByteArrayInputStream(new byte[100]), 10);
        input.read(new byte[10]);

        // When / Then
        assertThatThrownBy(() -> input.read())
                .isInstanceOf(LimitExceededException.class);
    }
    // endregion
}
