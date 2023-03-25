/*
 * Copyright © 2020, 2021, 2022, 2023 Peter Doornbosch
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
package net.luminis.quic.send;

import net.luminis.quic.*;
import net.luminis.quic.frame.*;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.packet.ShortHeaderPacket;
import org.assertj.core.data.Percentage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import net.luminis.quic.test.FieldReader;
import net.luminis.quic.test.FieldSetter;

import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class GlobalPacketAssemblerTest extends AbstractSenderTest {

    private SendRequestQueue[] sendRequestQueues;
    private GlobalAckGenerator ackGenerator;
    private GlobalPacketAssembler globalPacketAssembler;

    @BeforeEach
    void initObjectUnderTest() {
        ackGenerator = new GlobalAckGenerator(mock(Sender.class));
        sendRequestQueues = new SendRequestQueue[4];
        for (int i = 0; i < 4; i++) {
            sendRequestQueues[i] = new SendRequestQueue(EncryptionLevel.values()[i]);
        }
        globalPacketAssembler = new GlobalPacketAssembler(new VersionHolder(Version.getDefault()), sendRequestQueues, ackGenerator);
    }

    @Test
    void initialPacketMustBeGreaterThan1200Bytes() {
        sendRequestQueues[EncryptionLevel.Initial.ordinal()].addRequest(new CryptoFrame(Version.getDefault(), new byte[36]), f -> {});

        List<SendItem> packets = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);

        int datagramLength = packets.stream().mapToInt(p -> p.getPacket().estimateLength(0)).sum();
        assertThat(datagramLength).isGreaterThanOrEqualTo(1200);
    }

    @Test
    void packetContainingInitialPacketMustBeGreaterThan1200Bytes() {
        sendRequestQueues[EncryptionLevel.Initial.ordinal()].addRequest(new CryptoFrame(Version.getDefault(), new byte[36]), f -> {});
        sendRequestQueues[EncryptionLevel.Handshake.ordinal()].addRequest(new MaxDataFrame(105_000), f -> {});

        List<SendItem> packets = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);

        int datagramLength = packets.stream()
                .mapToInt(p -> p.getPacket().generatePacketBytes(levelKeys[p.getPacket().getEncryptionLevel().ordinal()]).length)
                .sum();
        assertThat(datagramLength).isGreaterThanOrEqualTo(1200);
        assertThat(datagramLength)
                .isGreaterThanOrEqualTo(1200)
                .isLessThanOrEqualTo(MAX_PACKET_SIZE);
    }

    @Test
    void nonInitialPacketHasMiniumSize() {
        globalPacketAssembler.enableAppLevel();
        sendRequestQueues[EncryptionLevel.App.ordinal()].addRequest(new CryptoFrame(Version.getDefault(), new byte[36]), f -> {});

        List<SendItem> packets = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);

        int datagramLength = packets.stream().mapToInt(p -> p.getPacket().generatePacketBytes(aead).length).sum();
        assertThat(datagramLength).isCloseTo(18 + 3 + 36, Percentage.withPercentage(5));
    }

    @Test
    void testInitialAckIsCombinedWithHandshakePacket() {
        ackGenerator.packetReceived(new MockPacket(0, 10, EncryptionLevel.Initial));
        sendRequestQueues[EncryptionLevel.Initial.ordinal()].addAckRequest();
        sendRequestQueues[EncryptionLevel.Handshake.ordinal()].addRequest(new MaxDataFrame(105_000), f -> {});

        List<SendItem> packets = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);

        assertThat(packets).hasSize(2);
    }

    @Test
    void largestPacketMustBeSmallerThenMaxPacketSize() throws Exception {
        setInitialPacketNumber(EncryptionLevel.App, 257);
        sendRequestQueues[EncryptionLevel.App.ordinal()].addRequest(
                (Integer size) -> new StreamFrame(0, new byte[size - 5], false),
                10,
                f -> {});

        List<SendItem> packets = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);

        int datagramLength = packets.stream()
                .mapToInt(p -> {
                    QuicPacket packet = p.getPacket();
                    byte[] generatedBytes = packet.generatePacketBytes(levelKeys[packet.getEncryptionLevel().ordinal()]);
                    return generatedBytes.length;
                })
                .sum();
        assertThat(datagramLength).isLessThanOrEqualTo(MAX_PACKET_SIZE);
    }

    @Test
    void multiplePacketsMustBeSmallerThenMaxPacketSize() throws Exception {
        sendRequestQueues[EncryptionLevel.Initial.ordinal()].addRequest(new CryptoFrame(Version.getDefault(), new byte[14]), f -> {});
        for (int i = 0; i < 30; i++) {
            sendRequestQueues[EncryptionLevel.ZeroRTT.ordinal()].addRequest(new StreamFrame(140, new byte[257], false), f -> {});
            sendRequestQueues[EncryptionLevel.ZeroRTT.ordinal()].addRequest(new StreamFrame(140, new byte[0], true), f -> {});
        }

        List<SendItem> packets = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);

        int datagramLength = packets.stream()
                .mapToInt(p -> {
                    QuicPacket packet = p.getPacket();
                    byte[] generatedBytes = packet.generatePacketBytes(levelKeys[packet.getEncryptionLevel().ordinal()]);
                    return generatedBytes.length;
                })
                .sum();
        assertThat(datagramLength).isLessThanOrEqualTo(MAX_PACKET_SIZE);
    }

    @Test
    void whenLevelIsAbandonedNoPacketsAreAssembledForThatLevel() {
        // Given
        sendRequestQueues[EncryptionLevel.Initial.ordinal()].addRequest(new MaxDataFrame(105_000), f -> {});

        // When
        globalPacketAssembler.stop(PnSpace.Initial);

        // Then
        List<SendItem> packets = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);
        assertThat(packets).isEmpty();
    }

    @Test
    void zeroRttPacketsShouldNeverContainAckFrames() throws Exception {
        // Given
        ackGenerator.packetReceived(new MockPacket(0, 10, EncryptionLevel.App));
        globalPacketAssembler.enableAppLevel();

        // When
        sendRequestQueues[EncryptionLevel.ZeroRTT.ordinal()].addRequest(new StreamFrame(140, new byte[257], false), f -> {});

        // Then
        List<SendItem> packets = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);
        assertThat(packets).hasSize(1);
        assertThat(packets.get(0).getPacket().getFrames()).doesNotHaveAnyElementsOfTypes(AckFrame.class);
    }

    @Test
    void zeroRttAndOneRttShouldNotUseSamePacketNumbers() {
        // Given
        globalPacketAssembler.enableAppLevel();
        sendRequestQueues[EncryptionLevel.ZeroRTT.ordinal()].addRequest(new StreamFrame(140, new byte[257], false), f -> {});
        sendRequestQueues[EncryptionLevel.App.ordinal()].addRequest(new StreamFrame(140, new byte[257], false), f -> {});

        // When
        List<SendItem> sendItems = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);
        List<QuicPacket> packets = sendItems.stream().map(item -> item.getPacket()).collect(Collectors.toList());

        // Then
        assertThat(packets.get(0).getEncryptionLevel() == EncryptionLevel.ZeroRTT);
        assertThat(packets.get(0).getEncryptionLevel() == EncryptionLevel.App);
        assertThat(packets.get(1).getPacketNumber()).isGreaterThan(packets.get(0).getPacketNumber());
    }

    @Test
    void totalSizeOfAssembledPacketsShouldBeLessThenMaxPacketSize() {
        sendRequestQueues[EncryptionLevel.ZeroRTT.ordinal()].addRequest(new StreamFrame(140, new byte[1000], false), f -> {});
        sendRequestQueues[EncryptionLevel.Handshake.ordinal()].addProbeRequest(List.of(new CryptoFrame(Version.getDefault(), 0, new byte[400])));

        // When
        List<SendItem> sendItems = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);
        List<QuicPacket> packets = sendItems.stream().map(item -> item.getPacket()).collect(Collectors.toList());
        int datagramPayloadSize = packets.stream().mapToInt(p -> p.estimateLength(0)).sum();

        assertThat(datagramPayloadSize).isLessThanOrEqualTo(MAX_PACKET_SIZE);
    }

    @Test
    void whenProbeDataIsLargerThenRemainingCwndItShouldBeUsed() {
        sendRequestQueues[EncryptionLevel.ZeroRTT.ordinal()].addRequest(new StreamFrame(140, new byte[1000], false), f -> {});
        sendRequestQueues[EncryptionLevel.Handshake.ordinal()].addProbeRequest(List.of(new CryptoFrame(Version.getDefault(), 0, new byte[400])));

        // When
        List<SendItem> sendItems = globalPacketAssembler.assemble(200, MAX_PACKET_SIZE, new byte[0], new byte[0]);
        List<QuicPacket> packets = sendItems.stream().map(item -> item.getPacket()).collect(Collectors.toList());

        // Then
        assertThat(packets).anyMatch(p -> p.getFrames().stream().allMatch(f -> f instanceof CryptoFrame));
    }

    @Test
    void whenCwndIsMinimalProbeShouldStillBeSent() {
        sendRequestQueues[EncryptionLevel.Handshake.ordinal()].addProbeRequest(List.of(new CryptoFrame(Version.getDefault(), 0, new byte[400])));

        // When
        List<SendItem> sendItems = globalPacketAssembler.assemble(0, MAX_PACKET_SIZE, new byte[0], new byte[0]);
        List<QuicPacket> packets = sendItems.stream().map(item -> item.getPacket()).collect(Collectors.toList());

        // Then
        assertThat(packets).anyMatch(p -> p.getFrames().stream().allMatch(f -> f instanceof CryptoFrame));
    }

    @Test
    void packetContainingPathResponseMustBeAtLeast1200Bytes() {
        globalPacketAssembler.enableAppLevel();
        sendRequestQueues[EncryptionLevel.App.ordinal()].addRequest(new PathResponseFrame(Version.getDefault(), new byte[8]), f -> {});

        List<SendItem> packets = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);

        int datagramLength = packets.stream().mapToInt(p -> p.getPacket().estimateLength(0)).sum();
        assertThat(datagramLength).isGreaterThanOrEqualTo(1200);
    }

    @Test
    void probeWithDataShouldNotExceedMaxDataframSize() {
        ackGenerator.packetReceived(new MockPacket(0, 10, EncryptionLevel.Initial));
        sendRequestQueues[EncryptionLevel.Initial.ordinal()].addAckRequest();
        sendRequestQueues[EncryptionLevel.Handshake.ordinal()].addProbeRequest(List.of(new CryptoFrame(Version.getDefault(), 0, new byte[1190])));

        List<SendItem> packets = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);

        int datagramLength = packets.stream().mapToInt(p -> p.getPacket().estimateLength(0)).sum();
        assertThat(datagramLength).isLessThanOrEqualTo(1232);
    }

    @Test
    void generatedDatagramShouldBeSmallerThanMaxDatagramSize() {
        globalPacketAssembler.enableAppLevel();
        sendRequestQueues[EncryptionLevel.App.ordinal()].addRequest(maxSize -> new StreamFrame(4, new byte[maxSize - 10], false), 10, f -> {});

        int maxDatagramSize = 700;
        List<SendItem> packets = globalPacketAssembler.assemble(6000, maxDatagramSize, new byte[0], new byte[0]);

        assertThat(packets.size()).isEqualTo(1);
        assertThat(packets.get(0).getPacket().estimateLength(0)).isLessThanOrEqualTo(maxDatagramSize);
    }

    @Test
    void ifInitialPacketsCannotStatisfyTheMinimum1200bytesRequirementItShouldNotBeSend() {
        sendRequestQueues[EncryptionLevel.Initial.ordinal()].addProbeRequest(List.of(new CryptoFrame(Version.getDefault(), new byte[123])));

        // Max datagram size can be limited by anti amplification limit
        int maxDatagramSize = 30;
        List<SendItem> packets = globalPacketAssembler.assemble(6000, maxDatagramSize, new byte[0], new byte[0]);
        assertThat(packets).isEmpty();
    }

    @Test
    void whenAppLevelNotEnabledAssemblerShouldNotCreateAppPackets() {
        // Given
        sendRequestQueues[EncryptionLevel.App.ordinal()].addAckRequest();
        sendRequestQueues[EncryptionLevel.App.ordinal()].addRequest(new StreamFrame(0, new byte[0], true), f -> {});

        // When
        List<SendItem> packets = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);

        // Then
        assertThat(packets).isEmpty();
    }

    @Test
    void whenAppLevelEnabledAssemblerShouldCreateAppPackets() {
        // Given
        sendRequestQueues[EncryptionLevel.App.ordinal()].addRequest(new StreamFrame(0, new byte[0], true), f -> {});
        globalPacketAssembler.enableAppLevel();

        // When
        List<SendItem> packets = globalPacketAssembler.assemble(6000, MAX_PACKET_SIZE, new byte[0], new byte[0]);

        // Then
        assertThat(packets).hasSize(1);
        assertThat(packets.get(0).getPacket()).isInstanceOf(ShortHeaderPacket.class);
    }

    private void setInitialPacketNumber(EncryptionLevel level, int pn) throws Exception {
        Object packetAssemblers = new FieldReader(globalPacketAssembler, globalPacketAssembler.getClass().getDeclaredField("packetAssembler")).read();
        PacketAssembler packetAssember = (PacketAssembler) ((Object[]) packetAssemblers)[level.ordinal()];
        FieldSetter.setField(packetAssember, packetAssember.getClass().getDeclaredField("nextPacketNumber"), pn);
    }
}
