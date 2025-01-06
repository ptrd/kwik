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
package tech.kwik.core.packet;

import tech.kwik.core.impl.InvalidPacketException;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.test.ByteUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class VersionNegotiationPacketTest {

    Logger log;

    @BeforeEach
    void initLogger() {
        log = mock(Logger.class);
    }

    @Test
    void parseFutureVersionPacketWithLongConnectionIds() throws Exception {
        String data = "ff 00 00 00 00 c8 " + generateHexBytes(200) + " c8 " + generateHexBytes(200) + " 00 00 00 01";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data.replace(" ", "")));

        VersionNegotiationPacket vn = new VersionNegotiationPacket();
        vn.parse(buffer, null, 0, log, 0);

        assertThat(vn.getServerSupportedVersions()).hasSize(1);
    }

    @Test
    void parsePacketWithInvalidDestConnectionIdLength() {
        String data = "ff 00 00 00 00 e4 01 02 03 04 05 06 07 08 08 01 02 03 04 05 06 07 08 08".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        assertThatThrownBy(
                () -> new VersionNegotiationPacket().parse(buffer, null, 0, log, 0)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parsePacketWithInvalidSrcConnectionIdLength() {
        String data = "ff 00 00 00 00 08 01 02 03 04 05 06 07 08 15 01 02 03 04 05 06 07 08 08".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        assertThatThrownBy(
                () -> new VersionNegotiationPacket().parse(buffer, null, 0, log, 0)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parsePacketWithoutSupportedVersion() {
        String data = "ff 00 00 00 00 04 01 02 03 04 04 01 02 03 04 0b 0b".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        assertThatThrownBy(
                () -> new VersionNegotiationPacket().parse(buffer, null, 0, log, 0)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void serializedVersionNegotationPacketHasTwoMostSignificantBitsSetToOne() throws Exception {
        // Given
        VersionNegotiationPacket versionNegotiationPacket = new VersionNegotiationPacket(Version.getDefault(), new byte[]{ 0x01, 0x02, 0x03, 0x04 }, new byte[]{ 0x0a, 0x0b, 0x0c, 0x0d });

        // When
        byte[] packetBytes = versionNegotiationPacket.generatePacketBytes(null);

        // Then
        assertThat(packetBytes[0] & 0b11000000).isEqualTo(0b11000000);
    }

    @Test
    void createVersionNegotationPacket() throws Exception {
        // Given
        VersionNegotiationPacket versionNegotiationPacket = new VersionNegotiationPacket(Version.getDefault(), new byte[]{ 0x01, 0x02, 0x03, 0x04 }, new byte[]{ 0x0a, 0x0b, 0x0c, 0x0d });
        byte[] packetBytes = versionNegotiationPacket.generatePacketBytes(null);
        
        // When
        VersionNegotiationPacket vnPacket = new VersionNegotiationPacket();
        vnPacket.parse(ByteBuffer.wrap(packetBytes), null, 0, log, 0);

        // Then
        assertThat(vnPacket.getSourceConnectionId()).isEqualTo(new byte[]{ 0x01, 0x02, 0x03, 0x04 });
        assertThat(vnPacket.getDestinationConnectionId()).isEqualTo(new byte[]{ 0x0a, 0x0b, 0x0c, 0x0d });
    }

    @Test
    void versionNegotiationPacketShouldHaveDcid() {
        VersionNegotiationPacket versionNegotiationPacket = new VersionNegotiationPacket(Version.getDefault(), new byte[] { 0x01, 0x02, 0x03, 0x04 }, new byte[] { 0x0a, 0x0b, 0x0c, 0x0d });

        assertThat(versionNegotiationPacket.getDestinationConnectionId()).isNotNull();
    }

    private String generateHexBytes(int length) {
        String result = IntStream.range(0, length).mapToObj(i -> String.format("%02x", i)).collect(Collectors.joining());
        return result;
    }

}