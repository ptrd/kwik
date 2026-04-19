/*
 * Copyright © 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.packet;

import tech.kwik.core.impl.InvalidPacketException;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.crypto.MissingKeysException;
import tech.kwik.core.log.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class ServerRolePacketParserTest {

    private ServerRolePacketParser parser;
    private ServerRolePacketParser retryRequiredParser;

    @BeforeEach
    void initObjectUnderTest() {
        Logger logger = mock(Logger.class);
        VersionHolder version = new VersionHolder(Version.QUIC_version_1);
        ConnectionSecrets connectionSecrets = new ConnectionSecrets(version, Role.Server, null, logger);
        parser = new ServerRolePacketParser(connectionSecrets, version, 0, false, null, null, logger);
        retryRequiredParser = new ServerRolePacketParser(connectionSecrets, version, 0, true, null, null, logger);
    }

    @Test
    void whenRetryRequiredAndTokenLengthEncodingIsTooLargeShouldThrowInvalidPacketException() throws Exception {
        // 0xc8: long header (bit 7), fixed bit (bit 6), Initial type (bits 5-4 = 00).
        // In getAead(), the token length field also reads as 0xc8 = 8-byte VLI with value > Integer.MAX_VALUE.
        byte[] data = new byte[1200];
        Arrays.fill(data, (byte) 0xc8);

        assertThatThrownBy(() -> retryRequiredParser.parsePacket(ByteBuffer.wrap(data)))
                .isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void whenRetryRequiredAndBufferTooShortToReadSrcCidLengthShouldThrowInvalidPacketException() throws Exception {
        // Minimal valid long-header Initial packet header, but destCidLength = 1 places srcCidLength
        // at index 7, which is beyond the buffer limit — IndexOutOfBoundsException in getAead().
        byte[] data = new byte[7];
        data[0] = (byte) 0xc0;                          // long header, fixed bit, Initial type
        data[1] = 0x00; data[2] = 0x00; data[3] = 0x00; data[4] = 0x01;  // QUIC v1
        data[5] = 1;                                     // destCidLength = 1
        data[6] = 0;                                     // first (only) byte of destCid; srcCidLength would be at index 7 — out of bounds

        assertThatThrownBy(() -> retryRequiredParser.parsePacket(ByteBuffer.wrap(data)))
                .isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void whenRetryRequiredAndCidLengthsCausesPositionBeyondBufferLimitShouldThrowInvalidPacketException() throws Exception {
        // destCidLength = 10, srcCidLength = 10 → data.position(27) on a 20-byte buffer — IllegalArgumentException in getAead().
        byte[] data = new byte[20];
        data[0] = (byte) 0xc0;                          // long header, fixed bit, Initial type
        data[1] = 0x00; data[2] = 0x00; data[3] = 0x00; data[4] = 0x01;  // QUIC v1
        data[5] = 10;                                    // destCidLength = 10
        data[16] = 10;                                   // srcCidLength = 10 (at index 6 + 10 = 16)
        // data.position(7 + 10 + 10) = 27 exceeds the buffer limit of 20

        assertThatThrownBy(() -> retryRequiredParser.parsePacket(ByteBuffer.wrap(data)))
                .isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void whenParsingZeroRttPacketItShouldFailOnMissingKeys() throws Exception {
        // Given
        byte[] data = { (byte) 0b11010001, 0x00, 0x00, 0x00, 0x01, 0, 0, 17, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        assertThatThrownBy(() ->
                // When
                parser.parsePacket(ByteBuffer.wrap(data))
        )
                // Then
                .isInstanceOf(MissingKeysException.class)
                .hasMessageContaining("ZeroRTT");
    }
}
