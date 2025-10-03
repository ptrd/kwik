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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.engine.TlsClientEngine;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.frame.*;
import tech.kwik.core.impl.InvalidPacketException;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.TestUtils;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.test.ByteUtils;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static tech.kwik.core.impl.Version.IETF_draft_29;

class HandshakePacketTest {

    private Aead aead;

    @BeforeEach
    void initDummyKeys() throws Exception {
        aead = TestUtils.createKeys();
    }

    @Test
    void parseCorrectlyEncryptedPacket() throws Exception {
        String data = "e5ff00001b040d0d0d0d040e0e0e0e1b4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.IETF_draft_27);
        handshakePacket.parse(buffer, aead, 0, mock(Logger.class), 4);
    }

    @Test
    void parseCorruptedPacketWithInvalidLength() throws Exception {
        String data = "e5ff00001b 040d0d0d0d0 40e0e0e0e 2b4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.IETF_draft_27);

        assertThatThrownBy(
                () -> handshakePacket.parse(buffer, aead, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseCorruptedPacketWithTooSmallLength() throws Exception {
        String data = "e5ff00001b 040d0d0d0d0 40e0e0e0e 004e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());

        assertThatThrownBy(
                () -> handshakePacket.parse(buffer, aead, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseCorruptedPacketWithInvalidDestinationConnectionIdLength() throws Exception {
        String data = "e5ff00001b f70d0d0d0d0 40e0e0e0e 1b4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());
        assertThatThrownBy(
                () ->         handshakePacket.parse(buffer, aead, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseCorruptedPacketWithInvalidSourceConnectionIdLength() throws Exception {
        String data = "e5ff00001b 040d0d0d0d eb0e0e0e0e 1b4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());
        assertThatThrownBy(
                () -> handshakePacket.parse(buffer, aead, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseCorruptedPacketIncorrectLengthCausesUnderflow() throws Exception {
        String data = "e5ff00001b 0f0d0d0d0d0 40e0e0e0e 1b4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());
        assertThatThrownBy(
                () -> handshakePacket.parse(buffer, aead, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void parseCorruptedPacketInvalidLengthCausesVarIntOverflow() throws Exception {
        String data = "e5ff00001b 040d0d0d0d0 40e0e0e0e fb4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());
        assertThatThrownBy(
                () -> handshakePacket.parse(buffer, aead, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void packetWithOtherVersionShouldBeIgnored() throws Exception {
        String data = "e5 0000000f 040d0d0d0d0 40e0e0e0e fb4e6f01d930078872bd5b3208c041a80cab857e6fa776b7fdb3b195".replace(" ", "");
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(data));

        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault());
        assertThatThrownBy(
                () -> handshakePacket.parse(buffer, aead, 0, mock(Logger.class), 4)
        ).isInstanceOf(InvalidPacketException.class);
    }

    @Test
    void packetWithMinimalFrameShouldBePaddedToGetEnoughBytesForEncrypting() throws Exception {
        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault(), new byte[]{ 0x0e, 0x0e, 0x0e, 0x0e }, new byte[]{ 0x0d, 0x0d, 0x0d, 0x0d }, new PingFrame());
        handshakePacket.setPacketNumber(1);

        Aead aead = TestUtils.createKeys();
        handshakePacket.generatePacketBytes(aead);

        // If it gets here, it is already sure the encryption succeeded.
        assertThat(handshakePacket.getFrames()).hasAtLeastOneElementOfType(PingFrame.class);
    }

    @Test
    void decrypt1() throws Exception {
        String data = "e2ff00001d0860db7d010bfe8e9b142fd392db1f7b727145856053759141c613e55a934487adfebeee055d91ae4b0240acb2ffe0188b1e8984534da56e3730740f5566d9cb922db5bbb7f39f16885fdf917e2549073e0abdacf38de6022aad66fefd0b2ae3ddfdf7a2fa9cb505eca00edf27079ed7210244f6c96acbd0dc1f05d5a4424d98446c05451ad1cf435291996953d14ab6c842b172bd02541769001c4ba403f229988c6583d6bfec5eb8af4a91a81cdbb1b053b5c545921c0165d6ac5cf04362fc631bc86cf3d6053d5cc850f0372b1f25f35b8af45e61244eea2ab22893f528b118351f6b36282de08a6f17f9b14ff2df521eaf5c35ac39e2a0a2e81301189bd50ce08201856275fc19cd9b1cb9d363f0db603e6ff758b01e93202a0a5a92878b894df6f3e7c3b21a9926bc0ab181e0301cd3520b1800a8404a4cbc4ac38b1150f66b52c20088d234b78e9e48a79c77c482affc9f9af705718d33825f7741dd57c7a16a1d3b65ec1badb8ed29740d042cc59be0da43cf19463e9982a8c8f32851b1febe87a28c001a3984c62e49b6c6015d29416528bf6da4eaa0fad22b49d46d22b4930238fedccad7aac176110110a7462878a74f983e1f20aa272b4ce639cdb7c4a120352ca0ec61e1bc2c22b3836c7af4ca37a5f320d506e8557c8756e983800967c69038e8a42f123f2311af166cc0b466d5e1c7a5a679d39831ac1bec81ad4d68abcea34886d6645a3e150f3fad143be78c49dd5747d395b293a656bac39875ceeede90e6f558bff44cad31b21e06eea7c18547eaf83db4bf50894a87465496f981723c829cd9eac410b349d3c4750e1ab58bbc7553b5684a8404a63089877a21c47200f298dff2a1172283779bec107385964feecc78a34bc9e193388e8f769480de90b2b693ec14f094b5732d863682a9d7e9b9909d7053f37267e897dfa4b8734d4c977daa5504a3a4524cbeacfe82e4d593127d1c13b44c87aaf862596434cf107c1449ad50e7eeb8a1d3b5a57c9a0e686f3eda91410249fc64a12dd25988e8362766300b8c203dbb20c9b3fba64115977be1f9c91ab8b9df338a11a29d948da064d82a6a18c31e568b63a86939999011564d7f511bbdc61535d52fabdfe5af818f60a66d41c37b8e952b219795dae9fe825a9d4636f0e9e2cbb818de3891df242f2401619110827abe304d0cc2c50a1771b505587c916b5406554bac030b3d1823c99700a28f1588291a589d4b5b5d112110c925b4762af68d61899471e60d5a5f197b7f5d1e302528467ee71744f48d8d68ebf3a5d842bb31ca8345f6baa2e1f7d1da79678339dfddcf00a5d5f6d024dd3e2dbbae47be36409b8087ddad6d71d25d4e67265cfed9949c810e5d955d5907a451f1ae12b29468dbcbd69a1e3efd1f70eece39fe2fa2672d8ba0e344f787e99086bfb4f6b7cb100e0db7fc720a2f882e92da6bc6e5e941e9893512559eb4bca257e23ac9cd175b40ea4d7f3fa3f44ff97c6d5391cfcdfcdff6b1f64f8183b97adac8d72013e797a47f9af106046c72d6cf88116f8b3760b5d244f4b70849255cdbfc4cf10b8f45b7a7eefd8b0140d8080f1eec27a5a86d14473218b8852c3eaf8994957215f3d69e1c664bbd0f5b49e03a697e33d6bfd83de11f5128f7ec3686c71967f099b3dfc7cef1b6cd850acaa9";
        ConnectionSecrets connectionSecrets = new ConnectionSecrets(VersionHolder.with(IETF_draft_29), Role.Client, null, mock(Logger.class));
        connectionSecrets.computeInitialKeys(ByteUtils.hexToBytes("861fcd50bdc4d34b"));

        TlsClientEngine tlsClientEngine = mock(TlsClientEngine.class);
        when(tlsClientEngine.getClientHandshakeTrafficSecret()).thenReturn(ByteUtils.hexToBytes("fdb5d43527aa9788cda8f8c00a56932f262ff48c43751de8939f14224788533f"));
        when(tlsClientEngine.getServerHandshakeTrafficSecret()).thenReturn(ByteUtils.hexToBytes("7021d58745bcb58ad38b442707e425a30d1cba3cde541c159d0d9d2d647ff9f2"));
        connectionSecrets.computeHandshakeSecrets(tlsClientEngine, TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);

        HandshakePacket handshakePacket = new HandshakePacket(IETF_draft_29);
        handshakePacket.parse(ByteBuffer.wrap(ByteUtils.hexToBytes(data)), connectionSecrets.getServerAead(EncryptionLevel.Handshake), 0, mock(Logger.class), 0);

        assertThat(handshakePacket.packetNumber).isEqualTo(0);
        assertThat(handshakePacket.frames).hasAtLeastOneElementOfType(CryptoFrame.class);
    }

    @Test
    void decrypt3() throws Exception {
        String data = "eeff00001d08375e1a9f9d7e49bd14e8ebf718bfe9d10f558ae55ed56b1ef95f013d8c17afef498063642e5d16dbce387cf7ebd38663c5aae7c392";
        ConnectionSecrets connectionSecrets = new ConnectionSecrets(VersionHolder.with(IETF_draft_29), Role.Client, null, mock(Logger.class));
        connectionSecrets.computeInitialKeys(ByteUtils.hexToBytes("1bc4ad22be1868b2"));

        TlsClientEngine tlsClientEngine = mock(TlsClientEngine.class);
        when(tlsClientEngine.getClientHandshakeTrafficSecret()).thenReturn(ByteUtils.hexToBytes("715177001489f23cf6922c83edfcb4ceb037c4a0a9088d91dda4bb96694cdfd0"));
        when(tlsClientEngine.getServerHandshakeTrafficSecret()).thenReturn(ByteUtils.hexToBytes("4cc9aad05d0b0d5fb07afbe4a40e4584cab6dc1f41fb6c79c78d3f7f834b0220"));
        connectionSecrets.computeHandshakeSecrets(tlsClientEngine, TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);

        QuicPacket packet = new HandshakePacket(IETF_draft_29);
        packet.parse(ByteBuffer.wrap(ByteUtils.hexToBytes(data)), connectionSecrets.getServerAead(EncryptionLevel.Handshake), 0, mock(Logger.class), 0);

        assertThat(packet.packetNumber).isEqualTo(9);
        assertThat(packet.frames).hasAtLeastOneElementOfType(AckFrame.class);
    }

    @Test
    void estimatedLength() throws Exception {
        byte[] srcCid = new byte[4];
        byte[] destCid = new byte[8];
        QuicFrame payload = new StreamFrame(0, new byte[80], true);
        QuicPacket packet = new HandshakePacket(Version.getDefault(), srcCid, destCid, payload);
        packet.setPacketNumber(0);

        int estimatedLength = packet.estimateLength(0);

        int actualLength = packet.generatePacketBytes(TestUtils.createKeys()).length;

        assertThat(actualLength).isLessThanOrEqualTo(estimatedLength);  // By contract!
        assertThat(actualLength).isEqualTo(estimatedLength);            // In practice
    }

    @Test
    void estimatedLengthWithLargePacketNumber() throws Exception {
        byte[] srcCid = new byte[4];
        byte[] destCid = new byte[8];
        QuicFrame payload = new StreamFrame(0, new byte[80], true);
        QuicPacket packet = new HandshakePacket(Version.getDefault(), srcCid, destCid, payload);
        packet.setPacketNumber(15087995);

        int estimatedLength = packet.estimateLength(0);

        int actualLength = packet.generatePacketBytes(TestUtils.createKeys()).length;

        assertThat(actualLength).isLessThanOrEqualTo(estimatedLength);  // By contract!
        assertThat(actualLength).isEqualTo(estimatedLength);            // In practice
    }

    @Test
    void estimatedLengthWithLargePacketNumberAndPayloadAroundMinVariableIntegerLength() throws Exception {
        byte[] srcCid = new byte[4];
        byte[] destCid = new byte[8];
        QuicFrame payload = new StreamFrame(0, new byte[41], true);
        QuicPacket packet = new HandshakePacket(Version.getDefault(), srcCid, destCid, payload);
        packet.setPacketNumber(15087995);

        int estimatedLength = packet.estimateLength(0);

        int actualLength = packet.generatePacketBytes(TestUtils.createKeys()).length;

        assertThat(actualLength).isLessThanOrEqualTo(estimatedLength);  // By contract!
        assertThat(actualLength).isEqualTo(estimatedLength);            // In practice
    }

    @Test
    void estimatedLengthWithMinimalLengthPacket() throws Exception {
        byte[] srcCid = new byte[0];
        byte[] destCid = new byte[0];
        QuicFrame payload = new PingFrame();
        HandshakePacket packet = new HandshakePacket(Version.getDefault(), srcCid, destCid, payload);
        packet.setPacketNumber(1);

        int estimatedLength = packet.estimateLength(0);

        int actualLength = packet.generatePacketBytes(TestUtils.createKeys()).length;

        assertThat(actualLength).isLessThanOrEqualTo(estimatedLength);  // By contract!
        assertThat(actualLength).isEqualTo(estimatedLength);            // In practice
    }

    @Test
    void estimatedLengthWithPayloadLengthJustBelowMinVariableIntegerLength() throws Exception {
        byte[] srcCid = new byte[0];
        byte[] destCid = new byte[0];
        QuicFrame payload = new CryptoFrame(Version.getDefault(), new byte[57]);
        int payloadLength = payload.getFrameLength();
        assertThat(payloadLength).isLessThan(64).isGreaterThan(48); // Just to be sure the test is valid: length + 16 must be > 63 and length < 63
        HandshakePacket packet = new HandshakePacket(Version.getDefault(), srcCid, destCid, payload);
        packet.setPacketNumber(1);

        int estimatedLength = packet.estimateLength(0);

        int actualLength = packet.generatePacketBytes(TestUtils.createKeys()).length;

        assertThat(actualLength).isLessThanOrEqualTo(estimatedLength);  // By contract!
        assertThat(actualLength).isEqualTo(estimatedLength);            // In practice
    }

    // Utility method to generate an encrypted and protected Handshake packet
    void generateHandshakePacket() throws Exception {
        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault(), new byte[]{ 0x0e, 0x0e, 0x0e, 0x0e }, new byte[]{ 0x0d, 0x0d, 0x0d, 0x0d }, new PingFrame());
        handshakePacket.addFrame(new Padding(9));

        Aead aead = TestUtils.createKeys();
        byte[] bytes = handshakePacket.generatePacketBytes(aead);
    }
}