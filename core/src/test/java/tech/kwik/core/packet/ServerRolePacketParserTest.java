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

import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.crypto.MissingKeysException;
import tech.kwik.core.log.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class ServerRolePacketParserTest {

    private ServerRolePacketParser parser;

    @BeforeEach
    void initObjectUnderTest() {
        Logger logger = mock(Logger.class);
        VersionHolder version = new VersionHolder(Version.QUIC_version_1);
        ConnectionSecrets connectionSecrets = new ConnectionSecrets(version, Role.Server, null, logger);
        parser = new ServerRolePacketParser(connectionSecrets, version, 0, false, null, null, logger);
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
