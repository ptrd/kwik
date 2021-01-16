/*
 * Copyright © 2020, 2021 Peter Doornbosch
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
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.crypto.Keys;
import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.frame.CryptoFrame;
import net.luminis.quic.log.Logger;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.*;
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

        InitialPacket initialPacket = new InitialPacket(Version.IETF_draft_27);

        ConnectionSecrets connectionSecrets = new ConnectionSecrets(Version.IETF_draft_27, Role.Client, null, logger);
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

        InitialPacket initialPacket = new InitialPacket(Version.IETF_draft_27);

        ConnectionSecrets connectionSecrets = new ConnectionSecrets(Version.getDefault(), Role.Client, null, logger);
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

        ConnectionSecrets connectionSecrets = new ConnectionSecrets(Version.getDefault(), Role.Client, null, logger);
        connectionSecrets.computeInitialKeys(ByteUtils.hexToBytes("dcd29c5480f39a24"));

        Keys keys = connectionSecrets.getServerSecrets(EncryptionLevel.Initial);

        assertThatThrownBy(() ->
                initialPacket.parse(ByteBuffer.wrap(ByteUtils.hexToBytes(data)), keys, 0, logger, 0)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void decrypt() throws Exception {
        String data = "ccff00001d08375e1a9f9d7e49bd14e8ebf718bfe9d10f558ae55ed56b1ef95f013d8c0041210b832235e803ddc629f3e614d6168361e7b1f48b0ec251ba4f1039c4d1c3d397733eab73515b95f76274b1240ba93f8858ac365a61d41894884f15c87e74a9e87c149f48fa6b07f0d2a52e7fef829ea8a35815771a70db0b11458dfc0f56c9b89a3cd205b52898b64a92e9a2880a571d2af24d978b2110d74a6f8a993442073ece74c626755df1165cd1fc89cca4f0bdfa965eec62557145a63ee0a05fe372e2fcaba92c25c9de1dbfdcad3e29fd19c39fcab47fbeb8588411566a047de41b5a304ebd0e79bd803288127d6e7490fdd31fd6aa04a01d91875d0fd0126e1ddb4b2ccff51fe0dc65a711147fe6450c751e5a66cf2ed2bebccc9986c8797f1179b34383c934cadaa2a035c1eca267d050fdecc3b9f5af46a677f5fb130c10bb757ba4";
        ConnectionSecrets connectionSecrets = new ConnectionSecrets(Version.getDefault(), Role.Client, null, mock(Logger.class));
        connectionSecrets.computeInitialKeys(ByteUtils.hexToBytes("1bc4ad22be1868b2"));
        Keys keys = connectionSecrets.getServerSecrets(EncryptionLevel.Initial);

        InitialPacket initialPacket = new InitialPacket(Version.getDefault());
        initialPacket.parse(ByteBuffer.wrap(ByteUtils.hexToBytes(data)), keys, 0, logger, 0);

        assertThat(initialPacket.packetNumber).isEqualTo(321);
        assertThat(initialPacket.frames)
                .hasAtLeastOneElementOfType(AckFrame.class)
                .hasAtLeastOneElementOfType(CryptoFrame.class);
    }

}