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
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class RetryPacketTest {

    public static final int DONT_CARE = -1;
    public static final String QUIC_VERSION_AS_HEX = String.format("%08x", Version.getDefault().getId());

    @Test
    void parseRetryPacket() throws Exception {
        String data = ("0f " + QUIC_VERSION_AS_HEX + "040d0d0d0d 040e0e0e0e 0102030405060708090a0b0c0d0e0f10").replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        RetryPacket retry = new RetryPacket(Version.getDefault());
        retry.parse(buffer, null, DONT_CARE, mock(Logger.class), DONT_CARE);

        assertThat(retry.getRetryToken()).hasSize(0);
        assertThat(retry.validateIntegrityTag(new byte[] { 0x0e, 0x0e, 0x0e, 0x0e })).isFalse();
    }

    @Test
    void parseEmtpyRetryPacket() throws Exception {
        ByteBuffer data = ByteBuffer.wrap(new byte[] { (byte) 0xf0 });

        assertThatThrownBy(() ->
                new RetryPacket(Version.getDefault()).parse(data, null, DONT_CARE, mock(Logger.class), DONT_CARE)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseRetryPacketWithIncompleteHeader() throws Exception {
        ByteBuffer data = ByteBuffer.wrap(new byte[] { (byte) 0xf0, 0x00, 0x00, 0x00, 0x01 });

        assertThatThrownBy(() ->
                new RetryPacket(Version.getDefault()).parse(data, null, DONT_CARE, mock(Logger.class), DONT_CARE)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void packetWithOtherVersionShouldBeIgnored() throws Exception {
        ByteBuffer data = ByteBuffer.wrap(new byte[] { (byte) 0xf0, 0x00, 0x00, 0x00, 0x0f, 0x04, 0x01, 0x02, 0x03, 0x04, 0x04, 0x01, 0x02, 0x03, 0x04 });

        assertThatThrownBy(() ->
                new RetryPacket(Version.getDefault()).parse(data, null, DONT_CARE, mock(Logger.class), DONT_CARE)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseRetryPacketWithInvalidSourceConnectionIdLength() throws Exception {
        String data = ("0f " + QUIC_VERSION_AS_HEX + "3f0d0d0d0d 040e0e0e0e").replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        assertThatThrownBy(() ->
                new RetryPacket(Version.getDefault()).parse(buffer, null, DONT_CARE, mock(Logger.class), DONT_CARE)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseRetryPacketWithInvalidSourceConnectionIdLength2() throws Exception {
        String data = ("0f " + QUIC_VERSION_AS_HEX + "180d0d0d0d 040e0e0e0e 0102030405060708090a0b0c0d0e0f").replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        assertThatThrownBy(() ->
                new RetryPacket(Version.getDefault()).parse(buffer, null, DONT_CARE, mock(Logger.class), DONT_CARE)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseRetryPacketWithInvalidDestinationConnectionIdLength() throws Exception {
        String data = ("0f " + QUIC_VERSION_AS_HEX + "040d0d0d0d 400e0e0e0e").replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        assertThatThrownBy(() ->
                new RetryPacket(Version.getDefault()).parse(buffer, null, DONT_CARE, mock(Logger.class), DONT_CARE)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseRetryPacketWithIncompleteRetryIntegrityTag() throws Exception {
        String data = ("0f " + QUIC_VERSION_AS_HEX + "040d0d0d0d 040e0e0e0e 0102030405060708090a0b0c0d0e").replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        assertThatThrownBy(() ->
                new RetryPacket(Version.getDefault()).parse(buffer, null, DONT_CARE, mock(Logger.class), DONT_CARE)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void serializeRetryPacket() throws Exception {
        byte[] scid = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7};
        byte[] dcid = new byte[] { 0, 1, 2, 3};
        byte[] odcid = new byte[] { 9, 9, 9, 9 };
        byte[] retryToken = new byte[32];
        byte[] packetBytes = new RetryPacket(Version.getDefault(), scid, dcid, odcid, retryToken).generatePacketBytes(null);

        RetryPacket deserializedPacket  = new RetryPacket(Version.getDefault());
        deserializedPacket.parse(ByteBuffer.wrap(packetBytes), null, DONT_CARE, mock(Logger.class), DONT_CARE);

        assertThat(deserializedPacket.getSourceConnectionId()).isEqualTo(scid);
        assertThat(deserializedPacket.getDestinationConnectionId()).isEqualTo(dcid);
        assertThat(deserializedPacket.getRetryToken()).isEqualTo(retryToken);
        assertThat(deserializedPacket.validateIntegrityTag(odcid)).isTrue();
    }
}
