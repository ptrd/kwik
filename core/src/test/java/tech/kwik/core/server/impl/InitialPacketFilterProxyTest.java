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
package tech.kwik.core.server.impl;

import tech.kwik.core.impl.Version;
import tech.kwik.core.log.LogProxy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.*;


class InitialPacketFilterProxyTest {

    private InitialPacketFilterProxy initialPacketFilterProxy;
    private ServerConnectionProxy connectionCandidate;

    @BeforeEach
    void initObjectUnderTest() {
        connectionCandidate = mock(ServerConnectionProxy.class);
        when(connectionCandidate.getOriginalDestinationConnectionId()).thenReturn(new byte[] { 0x01, 0x02, 0x03 });
        initialPacketFilterProxy = new InitialPacketFilterProxy(connectionCandidate, Version.QUIC_version_1, mock(LogProxy.class));
    }

    @Test
    void initialPacketShouldBeForwarded() {
        // Given
        byte[] initialPacket = new byte[] {(byte) 0b1100_0000, 0x00, 0x00, 0x00, 0x00 };

        // When
        initialPacketFilterProxy.parsePackets(0, Instant.now(), ByteBuffer.wrap(initialPacket), null);

        // Then
        verify(connectionCandidate).parsePackets(anyInt(), any(Instant.class), any(ByteBuffer.class), any());
    }

    @Test
    void handshakePacketShouldNotBeForwarded() {
        // Given
        byte[] handshakePacket = new byte[] {(byte) 0b1110_0000, 0x00, 0x00, 0x00, 0x00 };

        // When
        initialPacketFilterProxy.parsePackets(0, Instant.now(), ByteBuffer.wrap(handshakePacket), null);

        // Then
        verify(connectionCandidate, never()).parsePackets(anyInt(), any(Instant.class), any(ByteBuffer.class), any());
    }

    @Test
    void oneRttPacketShouldNotBeForwarded() {
        // Given
        byte[] appPacket = new byte[] {(byte) 0b0100_0000, 0x00, 0x00, 0x00, 0x00 };  // Short header packet!

        // When
        initialPacketFilterProxy.parsePackets(0, Instant.now(), ByteBuffer.wrap(appPacket), null);

        // Then
        verify(connectionCandidate, never()).parsePackets(anyInt(), any(Instant.class), any(ByteBuffer.class), any());
    }

    @Test
    void zeroRttPacketShouldBeForwarded() {
        // Given
        byte[] appPacket = new byte[] {(byte) 0b1101_0000, 0x00, 0x00, 0x00, 0x00 };

        // When
        initialPacketFilterProxy.parsePackets(0, Instant.now(), ByteBuffer.wrap(appPacket), null);

        // Then
        verify(connectionCandidate).parsePackets(anyInt(), any(Instant.class), any(ByteBuffer.class), any());
    }

    @Test
    void filterShouldNotChangePositionInByteBuffer() {
        // Given
        byte[] initialPacket = new byte[] { (byte) 0xdd, (byte) 0b1100_0000, 0x00, 0x00, 0x00, 0x00 };
        ByteBuffer buffer = ByteBuffer.wrap(initialPacket);
        buffer.position(1);
        int startPosition = buffer.position();

        // When
        initialPacketFilterProxy.parsePackets(0, Instant.now(), buffer, null);

        // Then
        assertThat(buffer.position()).isEqualTo(startPosition);
        assertThat(buffer.get()).isEqualTo((byte) 0b1100_0000);
    }
}
