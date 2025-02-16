/*
 * Copyright © 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;


class ConnectionCloseFrameTest {

    @Test
    void testGetFrameLength() {
        // Given
        ConnectionCloseFrame connectionCloseFrame = new ConnectionCloseFrame(Version.getDefault(), 77, "seventyseven");

        // When
        ByteBuffer buffer = ByteBuffer.allocate(100);
        connectionCloseFrame.serialize(buffer);
        buffer.flip();

        // Then
        assertThat(connectionCloseFrame.getFrameLength()).isEqualTo(buffer.remaining());
    }

    @Test
    void testGetFrameLength1d() {
        // Given
        ConnectionCloseFrame connectionCloseFrame = new ConnectionCloseFrame(Version.getDefault(), 0x010c, false, "http3 request cancelled");

        // When
        ByteBuffer buffer = ByteBuffer.allocate(100);
        connectionCloseFrame.serialize(buffer);
        buffer.flip();

        // Then
        assertThat(connectionCloseFrame.getFrameLength()).isEqualTo(buffer.remaining());
    }

    @Test
    void deserializeFrameWithApplicationError() throws Exception {
        // Given
        ConnectionCloseFrame connectionCloseFrame = new ConnectionCloseFrame(Version.getDefault(), 0x010c, false, "http3 request cancelled");
        ByteBuffer buffer = ByteBuffer.allocate(100);
        connectionCloseFrame.serialize(buffer);
        buffer.flip();

        // When
        ConnectionCloseFrame deserialized = new ConnectionCloseFrame(Version.getDefault()).parse(buffer, mock(Logger.class));

        // Then
        assertThat(deserialized.hasApplicationProtocolError()).isTrue();
        assertThat(deserialized.getErrorCode()).isEqualTo(0x010c);
    }
}
