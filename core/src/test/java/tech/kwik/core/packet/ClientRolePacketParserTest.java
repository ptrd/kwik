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

import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.impl.InvalidPacketException;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.test.ByteUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class ClientRolePacketParserTest {

    private PacketParser parser;

    @BeforeEach
    void initObjectUnderTest() {
        Logger logger = mock(Logger.class);
        VersionHolder version = new VersionHolder(Version.QUIC_version_1);
        ConnectionSecrets connectionSecrets = new ConnectionSecrets(version, Role.Server, null, logger);
        parser = new ClientRolePacketParser(connectionSecrets, version, 0, new byte[8], null, null, logger);
    }

    @Test
    void parsingValidVersionNegotiationPacketShouldSucceed() throws Exception {
        QuicPacket packet = parser.parsePacket(ByteBuffer.wrap(ByteUtils.hexToBytes("ff00000000040a0b0c0d040f0e0d0cff000018")));
        assertThat(packet).isInstanceOf(VersionNegotiationPacket.class);
    }

    @Test
    void parseEmptyPacket() throws Exception {
        assertThatThrownBy(
                () -> parser.parsePacket(ByteBuffer.wrap(new byte[0]))
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseLongHeaderPacketWithInvalidHeader1() throws Exception {
        assertThatThrownBy(
                () -> parser.parsePacket(ByteBuffer.wrap(new byte[] { (byte) 0xc0, 0x00}))
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseLongHeaderPacketWithInvalidHeader2() throws Exception {
        assertThatThrownBy(
                () -> parser.parsePacket(ByteBuffer.wrap(new byte[] { (byte) 0xc0, 0x00, 0x00, 0x00 }))
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseShortHeaderPacketWithInvalidHeader() throws Exception {
        assertThatThrownBy(
                () -> parser.parsePacket(ByteBuffer.wrap(new byte[] { (byte) 0x40 }))
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void clientParsingZeroRttPacketShouldThrow() throws Exception {
        assertThatThrownBy(() ->
                parser.parsePacket(ByteBuffer.wrap(new byte[] { (byte) 0b11010001, 0x00, 0x00, 0x00, 0x01, 0, 0, 17, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }))
        ).isInstanceOf(InvalidPacketException.class);
    }

}