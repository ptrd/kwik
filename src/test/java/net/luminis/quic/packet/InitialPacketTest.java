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
import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.frame.CryptoFrame;
import net.luminis.quic.log.Logger;
import net.luminis.tls.ByteUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class InitialPacketTest {

    private Logger logger;

    @BeforeEach
    void setUp() {
        logger = mock(Logger.class);
    }

    @Test
    void parseValidInitial() throws Exception {
        // Sample data: a Server Hello in a CryptoFrame and an AckFrame
        String data = "c8ff00001b08636130b594bd05140866f9c144c8450e3f00409794dd70c9438b56fc420920469d1eb0c76e7e69ce3d2e19811936a8804e94d6176c62903e25c422291b4427d00e5e169b10a9997513814a229b66fcba1d36385be2002d82ba9c97af81286ab3135becb6607a8a231fb1de77be0e55776d0c9c92dc1cb2a447b2d67bb2c528f7045816ec4c251e3fddc855d2feb3c22c1b03b8826dc94e9308da90653e905eb6be3408d3335408f32307c2";

        InitialPacket initialPacket = new InitialPacket(Version.getDefault());

        ConnectionSecrets connectionSecrets = new ConnectionSecrets(Version.getDefault(), null, logger);
        connectionSecrets.computeInitialKeys(ByteUtils.hexToBytes("dcd29c5480f39a24"));

        Keys keys = connectionSecrets.getServerSecrets(EncryptionLevel.Initial);
        initialPacket.parse(ByteBuffer.wrap(ByteUtils.hexToBytes(data)), keys, 0, logger, 0);

        assertThat(initialPacket.getToken()).isNullOrEmpty();
        assertThat(initialPacket.getFrames()).hasOnlyElementsOfTypes(CryptoFrame.class, AckFrame.class);
    }

    @Test
    void parseInitialWithTwoByteTokenLength() throws Exception {
        // Sample data: a Server Hello in a CryptoFrame and an AckFrame; the token length is artificially extended, so the packet won't decrypt
        String data = "c8ff00001b08636130b594bd05140866f9c144c8450e3f" + "4000" + "409794dd70c9438b56fc420920469d1eb0c76e7e69ce3d2e19811936a8804e94d6176c62903e25c422291b4427d00e5e169b10a9997513814a229b66fcba1d36385be2002d82ba9c97af81286ab3135becb6607a8a231fb1de77be0e55776d0c9c92dc1cb2a447b2d67bb2c528f7045816ec4c251e3fddc855d2feb3c22c1b03b8826dc94e9308da90653e905eb6be3408d3335408f32307c2";

        InitialPacket initialPacket = new InitialPacket(Version.getDefault());

        ConnectionSecrets connectionSecrets = new ConnectionSecrets(Version.getDefault(), null, logger);
        connectionSecrets.computeInitialKeys(ByteUtils.hexToBytes("dcd29c5480f39a24"));

        Keys keys = connectionSecrets.getServerSecrets(EncryptionLevel.Initial);
        assertThatThrownBy( () ->
                initialPacket.parse(ByteBuffer.wrap(ByteUtils.hexToBytes(data)), keys, 0, logger, 0)
        ).isInstanceOf(DecryptionException.class);   // Decryption will fail...

        // ... but the token is parsed already
        assertThat(initialPacket.getToken()).isNullOrEmpty();
    }

    @Test
    void parseInitialWithInvalidTokenLength() throws Exception {
        // Sample data: a Server Hello in a CryptoFrame and an AckFrame
        String data = "c8ff00001b08636130b594bd05140866f9c144c8450e3f" + "40df" + "409794dd70c9438b56fc420920469d1eb0c76e7e69ce3d2e19811936a8804e94d6176c62903e25c422291b4427d00e5e169b10a9997513814a229b66fcba1d36385be2002d82ba9c97af81286ab3135becb6607a8a231fb1de77be0e55776d0c9c92dc1cb2a447b2d67bb2c528f7045816ec4c251e3fddc855d2feb3c22c1b03b8826dc94e9308da90653e905eb6be3408d3335408f32307c2";

        InitialPacket initialPacket = new InitialPacket(Version.getDefault());

        ConnectionSecrets connectionSecrets = new ConnectionSecrets(Version.getDefault(), null, logger);
        connectionSecrets.computeInitialKeys(ByteUtils.hexToBytes("dcd29c5480f39a24"));

        Keys keys = connectionSecrets.getServerSecrets(EncryptionLevel.Initial);

        assertThatThrownBy(() ->
                initialPacket.parse(ByteBuffer.wrap(ByteUtils.hexToBytes(data)), keys, 0, logger, 0)
        ).isInstanceOf(InvalidPacketException.class);
    }

}