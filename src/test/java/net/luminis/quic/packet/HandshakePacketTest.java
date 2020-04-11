/*
 * Copyright © 2020 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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
package net.luminis.quic.packet;

import net.luminis.quic.*;
import net.luminis.quic.frame.Padding;
import net.luminis.quic.frame.PingFrame;
import net.luminis.quic.log.Logger;
import net.luminis.tls.ByteUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.internal.util.reflection.FieldSetter;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.interfaces.ECPublicKey;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HandshakePacketTest {

    private Keys keys;

    @BeforeEach
    void initDummyKeys() throws Exception {
        keys = mock(Keys.class);
        when(keys.getHp()).thenReturn(new byte[16]);
        when(keys.getWriteIV()).thenReturn(new byte[12]);
        when(keys.getWriteKey()).thenReturn(new byte[16]);
        Keys dummyKeys = new Keys(Version.getDefault(), new byte[16], null, mock(Logger.class));
        FieldSetter.setField(dummyKeys, Keys.class.getDeclaredField("hp"), new byte[16]);
        Cipher cipher = dummyKeys.getHeaderProtectionCipher();
        when(keys.getHeaderProtectionCipher()).thenReturn(cipher);
    }

    @Test
    void parseCorrectlyEncryptedPacket() throws Exception {
        String data = "e5ff00001b040d0d0d0d040e0e0e0e1b4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());
        handshakePacket.parse(buffer, keys, 0, mock(Logger.class), 4);
    }

    @Test
    void parseCorruptedPacketWithInvalidLength() throws Exception {
        String data = "e5ff00001b 040d0d0d0d0 40e0e0e0e 2b4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());

        assertThatThrownBy(
                () -> handshakePacket.parse(buffer, keys, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseCorruptedPacketWithTooSmallLength() throws Exception {
        String data = "e5ff00001b 040d0d0d0d0 40e0e0e0e 004e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());

        assertThatThrownBy(
                () -> handshakePacket.parse(buffer, keys, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseCorruptedPacketWithInvalidDestinationConnectionIdLength() throws Exception {
        String data = "e5ff00001b f70d0d0d0d0 40e0e0e0e 1b4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());
        assertThatThrownBy(
                () ->         handshakePacket.parse(buffer, keys, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseCorruptedPacketWithInvalidSourceConnectionIdLength() throws Exception {
        String data = "e5ff00001b 040d0d0d0d eb0e0e0e0e 1b4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());
        assertThatThrownBy(
                () -> handshakePacket.parse(buffer, keys, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseCorruptedPacketIncorrectLengthCausesUnderflow() throws Exception {
        String data = "e5ff00001b 0f0d0d0d0d0 40e0e0e0e 1b4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());
        assertThatThrownBy(
                () -> handshakePacket.parse(buffer, keys, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseCorruptedPacketInvalidLengthCausesVarIntOverflow() throws Exception {
        String data = "e5ff00001b 040d0d0d0d0 40e0e0e0e fb4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());
        assertThatThrownBy(
                () -> handshakePacket.parse(buffer, keys, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void packetWithOtherVersionShouldBeIgnored() throws Exception {
        String data = "e5 0000000f 040d0d0d0d0 40e0e0e0e fb4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());
        assertThatThrownBy(
                () -> handshakePacket.parse(buffer, keys, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }


    // Utility method to generate an encrypted and protected Handshake packet
    void generateHandshakePacket() {
        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault(), new byte[]{ 0x0e, 0x0e, 0x0e, 0x0e }, new byte[]{ 0x0d, 0x0d, 0x0d, 0x0d }, new PingFrame());
        handshakePacket.addFrame(new Padding(9));

        Keys keys = mock(Keys.class);
        when(keys.getHp()).thenReturn(new byte[16]);
        when(keys.getWriteIV()).thenReturn(new byte[12]);
        when(keys.getWriteKey()).thenReturn(new byte[16]);
        byte[] bytes = handshakePacket.generatePacketBytes(1, keys);
        System.out.println(ByteUtils.bytesToHex(bytes));

    }
}