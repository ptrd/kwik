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
package net.luminis.quic.send;

import net.luminis.quic.*;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.HandshakePacket;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.packet.ShortHeaderPacket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.internal.util.reflection.FieldSetter;

import javax.crypto.Cipher;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.data.Percentage.withPercentage;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PacketAssemblerTest {

    public static final int MAX_PACKET_SIZE = 1232;

    private static Keys keys;

    private SendRequestQueue sendRequestQueue;
    private InitialPacketAssembler initialPacketAssembler;
    private PacketAssembler handshakePacketAssembler;
    private PacketAssembler oneRttPacketAssembler;
    private AckGenerator initialAckGenerator;
    private AckGenerator handshakeAckGenerator;
    private AckGenerator oneRttAckGenerator;

    
    @BeforeEach
    void initKeys() throws Exception {
        keys = mock(Keys.class);
        when(keys.getHp()).thenReturn(new byte[16]);
        when(keys.getWriteIV()).thenReturn(new byte[12]);
        when(keys.getWriteKey()).thenReturn(new byte[16]);
        Keys dummyKeys = new Keys(Version.getDefault(), new byte[16], null, mock(Logger.class));
        FieldSetter.setField(dummyKeys, Keys.class.getDeclaredField("hp"), new byte[16]);
        Cipher hpCipher = dummyKeys.getHeaderProtectionCipher();
        when(keys.getHeaderProtectionCipher()).thenReturn(hpCipher);
        FieldSetter.setField(dummyKeys, Keys.class.getDeclaredField("writeKey"), new byte[16]);
        Cipher wCipher = dummyKeys.getWriteCipher();
        // The Java implementation of this cipher (GCM), prevents re-use with the same iv.
        // As various tests often use the same packet numbers (used for creating the nonce), the cipher must be re-initialized for each test.
        // Still, a consequence is that generatePacketBytes cannot be called twice on the same packet.
        when(keys.getWriteCipher()).thenReturn(wCipher);
        when(keys.getWriteKeySpec()).thenReturn(dummyKeys.getWriteKeySpec());
    }

    @BeforeEach
    void initObjectUnderTeset() {
        sendRequestQueue = new SendRequestQueue();
        initialAckGenerator = new AckGenerator();
        initialPacketAssembler = new InitialPacketAssembler(Version.getDefault(), MAX_PACKET_SIZE, sendRequestQueue, initialAckGenerator);
        handshakeAckGenerator = new AckGenerator();
        handshakePacketAssembler = new PacketAssembler(Version.getDefault(), EncryptionLevel.Handshake, MAX_PACKET_SIZE, sendRequestQueue, handshakeAckGenerator);
        oneRttAckGenerator = new AckGenerator();
        oneRttPacketAssembler = new PacketAssembler(Version.getDefault(), EncryptionLevel.App, MAX_PACKET_SIZE, sendRequestQueue, oneRttAckGenerator);

    }

    @Test
    void sendSingleShortPacket() {
        // Given
        byte[] destCid = new byte[] { 0x0c, 0x0a, 0x0f, 0x0e };

        // When
        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[7], true), 4 + 7, null);

        // Then
        QuicPacket packet = oneRttPacketAssembler.assemble(12000, 0, null, destCid).get();
        assertThat(packet).isInstanceOf(ShortHeaderPacket.class);
        assertThat(packet.getDestinationConnectionId()).isEqualTo(destCid);
        assertThat(packet.getFrames()).containsExactly(new StreamFrame(0, new byte[7], true));
        assertThat(packet.generatePacketBytes(0, keys).length).isLessThan(MAX_PACKET_SIZE);
    }

    @Test
    void sendSingleAck() {
        // Given
        oneRttAckGenerator.packetReceived(new MockPacket(0, 20, EncryptionLevel.App));

        // When
        sendRequestQueue.addAckRequest(0);    // This means the caller wants to send an _explicit_ ack.

        // Then
        QuicPacket packet = oneRttPacketAssembler.assemble(12000, 0, null, new byte[0]).get();
        assertThat(packet).isInstanceOf(ShortHeaderPacket.class);
        assertThat(packet.getFrames())
                .hasSize(1)
                .allSatisfy(frame -> {
            assertThat(frame).isInstanceOf(AckFrame.class);
            assertThat(((AckFrame) frame).getLargestAcknowledged()).isEqualTo(0);
        });
    }

    @Test
    void sendAckAndStreamData() {
        // Given
        oneRttAckGenerator.packetReceived(new MockPacket(0, 20, EncryptionLevel.App));
        oneRttAckGenerator.packetReceived(new MockPacket(3, 20, EncryptionLevel.App));
        oneRttAckGenerator.packetReceived(new MockPacket(8, 20, EncryptionLevel.App));
        oneRttAckGenerator.packetReceived(new MockPacket(10, 20, EncryptionLevel.App));

        // When
        sendRequestQueue.addAckRequest(0);
        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[maxSize - (3 + 2)], true),    // Stream length will be > 63, so 2 bytes for length field
                (3 + 2) + 1, null);  // Send at least 1 byte of data

        // Then
        QuicPacket packet = oneRttPacketAssembler.assemble(12000, 0, null, new byte[0]).get();
        assertThat(packet).isInstanceOf(ShortHeaderPacket.class);
        assertThat(packet.getFrames()).anySatisfy(frame -> {
            assertThat(frame).isInstanceOf(StreamFrame.class);
            assertThat(((StreamFrame) frame).getStreamData().length).isCloseTo(1200, withPercentage(0.5));
        });
        assertThat(packet.getFrames()).anySatisfy(frame -> {
            assertThat(frame).isInstanceOf(AckFrame.class);
            assertThat(((AckFrame) frame).getLargestAcknowledged()).isEqualTo(10);
        });
        assertThat(packet.generatePacketBytes(1, keys).length).isEqualTo(MAX_PACKET_SIZE);
    }

    @Test
    void sendMultipleFrames() {
        // When
        sendRequestQueue.addRequest(new MaxStreamDataFrame(0, 0x01000000000000l), null);   // 10 bytes
        sendRequestQueue.addRequest(new MaxDataFrame(0x05000000000000l), null);              //  9 bytes
        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[maxSize - (3 + 2)], true), (3 + 2) + 1, null);  // Stream length will be > 63, so 2 bytes

        // Then
        QuicPacket packet = oneRttPacketAssembler.assemble(12000, 0, null, new byte[0]).get();
        assertThat(packet.getFrames()).hasOnlyElementsOfTypes(MaxStreamDataFrame.class, MaxDataFrame.class, StreamFrame.class);
        assertThat(packet.getFrames()).anySatisfy(frame -> {
            assertThat(frame).isInstanceOf(StreamFrame.class);
            // Short packet overhead is 18, so available for stream frame: 1232 - 18 - 10 - 9 = 1195. Frame overhead: 5 bytes.
            assertThat(((StreamFrame) frame).getStreamData().length).isCloseTo(1190, withPercentage(0.1));
        });
        assertThat(packet.generatePacketBytes(1, keys).length).isEqualTo(MAX_PACKET_SIZE);
    }

    @Test
    void whenFirstFrameDoesNotFitFindOneThatDoes() {
        // Given
        int remainingCwndSize = 25;  // Which leaves room for approx 7 bytes payload.

        // When
        sendRequestQueue.addRequest(new MaxStreamDataFrame(0, 0x01000000000000l), null);  // 10 bytes frame length
        sendRequestQueue.addRequest(new DataBlockedFrame(60), null);  // 2 bytes frame length
        sendRequestQueue.addRequest(maxSize ->
                        new StreamFrame(0, new byte[Integer.min(maxSize, 63) - (3 + 1)], true),
                        5, null);

        // Then
        QuicPacket packet = oneRttPacketAssembler.assemble(remainingCwndSize, 0, new byte[0], new byte[0]).get();
        assertThat(packet.getFrames())
                .hasAtLeastOneElementOfType(DataBlockedFrame.class)
                .hasAtLeastOneElementOfType(StreamFrame.class);
        assertThat(packet.generatePacketBytes(0, keys).length).isLessThanOrEqualTo(remainingCwndSize);
    }

    @Test
    void sendHandshakePacketWithMaxLengthCrypto() {
        // Given
        byte[] srcCid = new byte[] { (byte) 0xba, (byte) 0xbe };
        byte[] destCid = new byte[] { 0x0c, 0x0a, 0x0f, 0x0e };

        // When
        sendRequestQueue.addRequest(maxSize -> new CryptoFrame(Version.getDefault(), 0, new byte[maxSize - (3 + (maxSize < 64? 1: 2))]), (3 + 2) + 1, null);

        // Then
        QuicPacket packet = handshakePacketAssembler.assemble(12000, 0, srcCid, destCid).get();
        assertThat(packet).isInstanceOf(HandshakePacket.class);
        assertThat(((HandshakePacket) packet).getSourceConnectionId()).isEqualTo(srcCid);
        assertThat(packet.getDestinationConnectionId()).isEqualTo(destCid);
        assertThat(packet.getFrames())
                .hasSize(1)
                .hasOnlyElementsOfTypes(CryptoFrame.class);
        assertThat(packet.generatePacketBytes(0, keys).length).isEqualTo(MAX_PACKET_SIZE);
    }

    @Test
    void sendInitialPacketWithToken() {
        // Given
        byte[] srcCid = new byte[] { (byte) 0xba, (byte) 0xbe };
        byte[] destCid = new byte[] { 0x0c, 0x0a, 0x0f, 0x0e };
        initialPacketAssembler.setInitialToken(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f });

        // When
        sendRequestQueue.addRequest(maxSize -> new CryptoFrame(Version.getDefault(), 0, new byte[234]), (3 + 2) + 234, null);

        // Then
        QuicPacket packet = initialPacketAssembler.assemble(12000, 0, srcCid, destCid).get();
        assertThat(packet).isInstanceOf(InitialPacket.class);
        assertThat(((InitialPacket) packet).getSourceConnectionId()).isEqualTo(srcCid);
        assertThat(packet.getDestinationConnectionId()).isEqualTo(destCid);
        assertThat(packet.getFrames())
                .hasSize(2)
                .hasOnlyElementsOfTypes(CryptoFrame.class, Padding.class);
        assertThat(((InitialPacket) packet).getToken()).hasSize(16);
        assertThat(packet.generatePacketBytes(0, keys).length)
                .isGreaterThanOrEqualTo(1200)
                .isLessThanOrEqualTo(MAX_PACKET_SIZE);
    }

    @Test
    void sendInitialPacketWithoutToken() {
        // Given
        byte[] srcCid = new byte[] { (byte) 0xba, (byte) 0xbe };
        byte[] destCid = new byte[] { 0x0c, 0x0a, 0x0f, 0x0e };

        // When
        sendRequestQueue.addRequest(maxSize -> new CryptoFrame(Version.getDefault(), 0, new byte[234]), (3 + 2) + 234, null);

        // Then
        QuicPacket packet = initialPacketAssembler.assemble(12000, 0, srcCid, destCid).get();
        assertThat(packet).isInstanceOf(InitialPacket.class);
        assertThat(((InitialPacket) packet).getSourceConnectionId()).isEqualTo(srcCid);
        assertThat(packet.getDestinationConnectionId()).isEqualTo(destCid);
        assertThat(packet.getFrames())
                .hasSize(2)
                .hasOnlyElementsOfTypes(CryptoFrame.class, Padding.class);
        assertThat(packet.generatePacketBytes(0, keys).length)
                .isGreaterThanOrEqualTo(1200)
                .isLessThanOrEqualTo(MAX_PACKET_SIZE);
    }

    @Test
    void anyInitialPacketShouldHaveToken() {
        // Given
        initialPacketAssembler.setInitialToken(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 });
        initialAckGenerator.packetReceived(new MockPacket(0, 20, EncryptionLevel.Initial));

        // When
        sendRequestQueue.addAckRequest(0);    // This means the caller wants to send an _explicit_ ack.

        // Then
        InitialPacket packet = (InitialPacket) initialPacketAssembler.assemble(12000, 0, new byte[0], new byte[0]).get();
        assertThat(packet.getFrames())
                .hasOnlyElementsOfTypes(AckFrame.class, Padding.class);
        assertThat(packet.getToken()).hasSize(8);
        assertThat(packet.generatePacketBytes(0, keys).length)
                .isGreaterThanOrEqualTo(1200)
                .isLessThanOrEqualTo(MAX_PACKET_SIZE);
    }

    @Test
    void whenNothingToSendDelayedAckIsSendAfterDelay() throws Exception {
        // Given
        int ackDelay = 10;

        // When
        oneRttAckGenerator.packetReceived(new MockPacket(0, 20, EncryptionLevel.App));
        sendRequestQueue.addAckRequest(ackDelay);

        // Then
        Optional<QuicPacket> firstCheck = oneRttPacketAssembler.assemble(12000, 0, null, new byte[]{ (byte) 0xdc, 0x1d });

        // When
        Thread.sleep(ackDelay);

        // Then
        QuicPacket packet = oneRttPacketAssembler.assemble(12000, 0, null, new byte[]{ (byte) 0xdc, 0x1d }).get();
        assertThat(firstCheck).isEmpty();
        assertThat(packet).isNotNull();
        assertThat(packet.getFrames()).allSatisfy(frame -> {
            assertThat(frame).isInstanceOf(AckFrame.class);
            assertThat(((AckFrame) frame).getAckDelay()).isGreaterThanOrEqualTo(ackDelay);
        });
    }

    @Test
    void whenSendingDataSentPacketWillIncludeAck() throws Exception {
        // Given
        oneRttAckGenerator.packetReceived(new MockPacket(0, 20, EncryptionLevel.App));
        oneRttAckGenerator.packetReceived(new MockPacket(3, 20, EncryptionLevel.App));
        oneRttAckGenerator.packetReceived(new MockPacket(8, 20, EncryptionLevel.App));

        // When
        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[32], true), 37, null);

        // Then
        QuicPacket packet = oneRttPacketAssembler.assemble(12000, 0, null, new byte[0]).get();
        assertThat(packet).isInstanceOf(ShortHeaderPacket.class);
        assertThat(packet.getFrames())
                .hasSize(2)
                .hasOnlyElementsOfTypes(StreamFrame.class, AckFrame.class)
                .anySatisfy(frame -> {
            assertThat(frame).isInstanceOf(AckFrame.class);
            assertThat(((AckFrame) frame).getLargestAcknowledged()).isEqualTo(8);
        });
    }

    @Test
    void whenNoDataToSendButAnExplicitAckIsQueueAssembleWillCreateAckOnlyPacket() throws Exception {
        // Given
        oneRttAckGenerator.packetReceived(new MockPacket(0, 20, EncryptionLevel.App));

        // When
        sendRequestQueue.addAckRequest();

        // Then
        QuicPacket packet = oneRttPacketAssembler.assemble(12000, 0, null, new byte[0]).get();
        assertThat(packet).isNotNull();
        assertThat(packet.getFrames())
                .hasSize(1)
                .hasOnlyElementsOfType(AckFrame.class);
    }

    @Test
    void whenNoDataToSendAndNoExcplicitAckToSendAssembleWillNotGenerateAckOnlyPacket() throws Exception {
        // Given
        oneRttAckGenerator.packetReceived(new MockPacket(0, 20, EncryptionLevel.App));

        // When
        // Nothing, no explicit ack requested

        // Then
        Optional<QuicPacket> packet = oneRttPacketAssembler.assemble(12000, 0, null, new byte[0]);
        assertThat(packet).isEmpty();
    }

    @Test
    void whenCwndReachedNoDataIsSent() {
        // When
        sendRequestQueue.addRequest(new MaxDataFrame(102_000), null);
        int currentCwndRemaining = 16;

        // Then
        Optional<QuicPacket> packet = oneRttPacketAssembler.assemble(currentCwndRemaining, 0, null, new byte[0]);
        assertThat(packet).isEmpty();
    }

    @Test
    void whenAddingProbeAndRequestListIsEmptyThenPingFrameShouldBeSent() {
        // When
        sendRequestQueue.addProbeRequest();

        // Then
        QuicPacket packet = oneRttPacketAssembler.assemble(12000, 0, null, new byte[0]).get();
        assertThat(packet).isNotNull();
        assertThat(packet.getFrames())
                .hasSize(1)
                .hasOnlyElementsOfType(PingFrame.class);
    }

    @Test
    void whenCwndReachedSendingProbeLeadsToSinglePing() {
        // When
        int currentCwndRemaining = 16;
        sendRequestQueue.addRequest(new MaxDataFrame(102_000), null);
        sendRequestQueue.addProbeRequest();

        // Then
        QuicPacket packet = oneRttPacketAssembler.assemble(currentCwndRemaining, 0, null, new byte[0]).get();
        assertThat(packet).isNotNull();
        assertThat(packet.getFrames())
                .hasSize(1)
                .hasOnlyElementsOfType(PingFrame.class);

        // And
        Optional<QuicPacket> another = oneRttPacketAssembler.assemble(currentCwndRemaining, 0, null, new byte[0]);
        assertThat(another).isEmpty();
    }

    @Test
    void whenAddingProbeToNonEmptySendQueueAndCwndIsLargeEnoughTheNextPacketIsSent() {
        // When
        sendRequestQueue.addRequest(new MaxDataFrame(102_000), null);
        sendRequestQueue.addProbeRequest();

        // Then
        QuicPacket packet = oneRttPacketAssembler.assemble(60, 0, null, new byte[0]).get();
        assertThat(packet).isNotNull();
        assertThat(packet.getFrames())
                .hasSize(1)
                .hasOnlyElementsOfType(MaxDataFrame.class);
    }

    @Test
    void whenProbeContainsDataThisIsSendInsteadOfQueuedFrames() {
        // When
        sendRequestQueue.addRequest(new MaxDataFrame(102_000), null);
        sendRequestQueue.addProbeRequest(List.of(new CryptoFrame(Version.getDefault(), 0, new byte[100])));

        // Then
        QuicPacket packet = oneRttPacketAssembler.assemble(1200, 0, null, new byte[0]).get();
        assertThat(packet).isNotNull();
        assertThat(packet.getFrames())
                .hasSize(1)
                .hasOnlyElementsOfType(CryptoFrame.class);
    }
}