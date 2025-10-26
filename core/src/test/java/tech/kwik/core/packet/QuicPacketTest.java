/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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

import org.junit.jupiter.api.Test;
import tech.kwik.core.frame.AckFrame;
import tech.kwik.core.frame.DatagramFrame;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class QuicPacketTest {

    @Test
    void testConvertOneByteToInt() {
        assertThat(QuicPacket.bytesToInt(new byte[] { 0x0f })).isEqualTo(15);
        assertThat(QuicPacket.bytesToInt(new byte[] { (byte) 0xff })).isEqualTo(255);
    }

    @Test
    void testConvertTwoBytesToInt() {
        assertThat(QuicPacket.bytesToInt(new byte[] { 0x03, 0x45 })).isEqualTo(837);
        assertThat(QuicPacket.bytesToInt(new byte[] { (byte) 0xd3, (byte) 0xe4 })).isEqualTo(54244);
    }

    @Test
    void testConvertThreeBytesToInt() {
        assertThat(QuicPacket.bytesToInt(new byte[] { 0x03, 0x45, 0x67 })).isEqualTo(214375);
        assertThat(QuicPacket.bytesToInt(new byte[] { (byte) 0xd3, (byte) 0xe4, (byte) 0xf5 })).isEqualTo(13886709);
    }

    @Test
    void testConvertFourBytesToInt() {
        assertThat(QuicPacket.bytesToInt(new byte[] { 0x03, 0x45, 0x67, (byte) 0x89 })).isEqualTo(54880137);
        // Java int is signed, so cannot hold max 32 bits value....
        // assertThat(QuicPacket.bytesToInt(new byte[] { (byte) 0xc2, (byte) 0xd3, (byte) 0xe4, (byte) 0xf5 })).isEqualTo(3268666613);
    }

    @Test
    void encodeSingleBytePacketNumber() {
        assertThat(QuicPacket.encodePacketNumber(0x77)).isEqualTo(new byte[] { 0x77 });
        byte newFlags = QuicPacket.encodePacketNumberLength((byte) 0x00, 0x77);
        assertThat(newFlags).isEqualTo((byte) 0x00);
    }

    @Test
    void encodeMaxSingleBytePacketNumber() {
        assertThat(QuicPacket.encodePacketNumber(0x00ff)).isEqualTo(new byte[] { (byte) 0xff });
        byte newFlags = QuicPacket.encodePacketNumberLength((byte) 0x00, 0xff);
        assertThat(newFlags).isEqualTo((byte) 0x00);
    }

    @Test
    void encodeTwoBytePacketNumber() {
        int pn = 0x045a;
        assertThat(QuicPacket.encodePacketNumber(pn)).isEqualTo(new byte[] { 0x04, 0x5a });
        byte newFlags = QuicPacket.encodePacketNumberLength((byte) 0x00, pn);
        assertThat(newFlags).isEqualTo((byte) 0x01);
    }

    @Test
    void encodeMaxTwoBytePacketNumber() {
        int pn = 0xffff;
        assertThat(QuicPacket.encodePacketNumber(pn)).isEqualTo(new byte[] { (byte) 0xff, (byte) 0xff });
        byte newFlags = QuicPacket.encodePacketNumberLength((byte) 0x00, pn);
        assertThat(newFlags).isEqualTo((byte) 0x01);
    }

    @Test
    void encodeThreeBytePacketNumber() {
        int pn = 0x00aaff11;
        assertThat(QuicPacket.encodePacketNumber(pn)).isEqualTo(new byte[] { (byte) 0xaa, (byte) 0xff, 0x11 });
        byte newFlags = QuicPacket.encodePacketNumberLength((byte) 0x00, pn);
        assertThat(newFlags).isEqualTo((byte) 0x02);
    }

    @Test
    void encodeMaxThreeBytePacketNumber() {
        int pn = 0x00ffffff;
        assertThat(QuicPacket.encodePacketNumber(pn)).isEqualTo(new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff });
        byte newFlags = QuicPacket.encodePacketNumberLength((byte) 0x00, pn);
        assertThat(newFlags).isEqualTo((byte) 0x02);
    }

    @Test
    void encodeFourBytePacketNumber() {
        long pn = 0x33aaff11L;
        assertThat(QuicPacket.encodePacketNumber(pn)).isEqualTo(new byte[] { 0x33, (byte) 0xaa, (byte) 0xff, 0x11 });
        byte newFlags = QuicPacket.encodePacketNumberLength((byte) 0x00, pn);
        assertThat(newFlags).isEqualTo((byte) 0x03);
    }

    @Test
    void encodeMaxFourBytePacketNumber() {
        long pn = 0xffffffffL;
        assertThat(QuicPacket.encodePacketNumber(pn)).isEqualTo(new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff });
        byte newFlags = QuicPacket.encodePacketNumberLength((byte) 0x00, pn);
        assertThat(newFlags).isEqualTo((byte) 0x03);
    }

    @Test
    void decodeFullyEncodedPacketNumber() {
        long pn = QuicPacket.decodePacketNumber(65455, 65454, 16);
        assertThat(pn).isEqualTo(65455);
    }

    //   0               256              512              768              1024
    //   |................|................|................|................|
    //                             e                                                e = expected
    //                     -------384------
    //
    // received pn: 44
    //     44               300               556                                   possible values
    @Test
    void decodeTruncatedPacketNumberCandidateIsRight() {
        long pn = QuicPacket.decodePacketNumber(44, 384, 8);
        assertThat(pn).isEqualTo(300);
    }

    //   0               256              512              768              1024
    //   |................|................|................|................|
    //                      e                                                       e = expected
    //              -------268------
    //
    // received pn: 254
    //                  254             510              766                        possible values
    @Test
    void decodeTruncatedPacketNumberCandidateIsTooLarge() {
        long pn = QuicPacket.decodePacketNumber(254, 268, 8);
        assertThat(pn).isEqualTo(254);
    }

    //   0               256              512              768              1024
    //   |................|................|................|................|
    //                                    e                                         e = expected
    //                            -------510------
    //
    // received pn: 10
    //     10               266              522              778                   possible values
    @Test
    void decodeTruncatedPacketNumberCandidateIsTooSmall() {
        long pn = QuicPacket.decodePacketNumber(10, 510, 8);
        assertThat(pn).isEqualTo(522);
    }

    @Test
    void decodeFourBytesPacketNumber() {
        long pn = QuicPacket.decodePacketNumber(65455, 65454, 32);
        assertThat(pn).isEqualTo(65455);
    }

    //   0                    4294967296               8589934592
    //   |........................|........................|.................
    //                                                                           e = expected
    //                             -4494967300-
    //
    // received pn: 200000004
    @Test
    void decodeFourBytesTruncatedPacketNumber() {
        long pn = QuicPacket.decodePacketNumber(200000004, 4494967299L, 32);
        assertThat(pn).isEqualTo(4494967300L);
    }

    //              1690820096                        1690820352
    //   ................|.................................|...........................
    //                                                    e                              e = expected
    //                                    ------------1690820351-------------
    //                               1690820224                         1690820480       window
    // received pn: 0
    //              1690820096                        1690820352                        1690820608    possible values
    @Test
    void decodeOneByteTruncatedPacketNumberWithLargeExpected() {
        long pn = QuicPacket.decodePacketNumber(0, 1690820350, 8);
        assertThat(pn).isEqualTo(1690820352);
    }

    @Test
    void byteToIntShouldWorkForVeryLargeValues() {
        // Given
        byte[] unprotectedPacketNumber = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

        // When
        long candidatePacketNumber = QuicPacket.bytesToInt(unprotectedPacketNumber);

        // Then
        assertThat(candidatePacketNumber).isEqualTo(0x00000000ffffffffL);
    }

    @Test
    void parseMaxStreamsFrameWithInvalidIntegerEncodingShouldLeadToFrameEncodingError() {
        // Given
        byte[] data = new byte[] { 0x12, 0b0100_1010 };

        // When
        QuicPacket packet = new ShortHeaderPacket(Version.getDefault());
        assertThatThrownBy(() -> packet.parseFrames(data, mock(Logger.class)))
                // Then
                .isInstanceOf(TransportError.class)
                .hasMessageContaining("FRAME_ENCODING_ERROR");
    }

    @Test
    void parseNewTokenFrameWithTokenLargerThanFrameShouldLeadToFrameEncodingError() {
        // Given
        byte[] data = new byte[] { 0x07, 0x20,
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08 };

        // When
        QuicPacket packet = new ShortHeaderPacket(Version.getDefault());
        assertThatThrownBy(() -> packet.parseFrames(data, mock(Logger.class)))
                // Then
                .isInstanceOf(TransportError.class)
                .hasMessageContaining("FRAME_ENCODING_ERROR");
    }

    @Test
    void parsingNewTokenFrameWithZeroLengthConnectionIdShouldThrow() throws Exception {
        // Given                   type  seq   prior connection id length
        byte[] data = new byte[] { 0x18, 0x01, 0x00, 0x00,
                // and 128 bits of stateless reset token
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
                (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F };
        QuicPacket packet = new ShortHeaderPacket(Version.getDefault());

        // When
        assertThatThrownBy(() -> packet.parseFrames(data, mock(Logger.class)))
                // Then
                .isInstanceOf(TransportError.class)
                .hasMessageContaining("FRAME_ENCODING_ERROR");
    }

    @Test
    void parsingNewTokenFrameWithConnectionIdLengthGreaterThan20ShouldThrow() throws Exception {
        // Given                   type  seq   prior connection id length
        byte[] data = new byte[] { 0x18, 0x01, 0x00, 0x15,
                // connection id, 21 bytes
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09,
                (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F, (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
                (byte)0x14,
                // and 128 bits of stateless reset token
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
                (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F };
        QuicPacket packet = new ShortHeaderPacket(Version.getDefault());

        // When
        assertThatThrownBy(() -> packet.parseFrames(data, mock(Logger.class)))
                // Then
                .isInstanceOf(TransportError.class)
                .hasMessageContaining("FRAME_ENCODING_ERROR");
    }

    @Test
    void parseDatagramFrameWithoutLengthField() throws Exception {
        // Given
        byte[] data = new byte[] { 0x30, 0x71, 0x75, 0x69, 0x63 };
        QuicPacket packet = new ShortHeaderPacket(Version.getDefault());

        // When
        packet.parseFrames(data, mock(Logger.class));

        // Then
        assertThat(packet.getFrames()).hasOnlyElementsOfType(DatagramFrame.class);
    }

    @Test
    void parseDatagramFrameWithLengthField() throws Exception {
        // Given
        byte[] data = new byte[] { 0x31, 0x04, 0x71, 0x75, 0x69, 0x63 };
        QuicPacket packet = new ShortHeaderPacket(Version.getDefault());

        // When
        packet.parseFrames(data, mock(Logger.class));

        // Then
        assertThat(packet.getFrames()).hasOnlyElementsOfType(DatagramFrame.class);
    }

    //region packet properties
    @Test
    void packetWithOnlyAnAckIsAckOnly() throws Exception {
        // Given
        QuicPacket packet = new ShortHeaderPacket(Version.getDefault());
        packet.addFrame(new AckFrame(8));

        // When / Then
        assertThat(packet.isAckOnly()).isTrue();
    }

    @Test
    void packetWithAckAndNonAckIsNotAckOnly() throws Exception {
        // Given
        QuicPacket packet = new ShortHeaderPacket(Version.getDefault());
        packet.addFrame(new AckFrame(8));
        packet.addFrame(new StreamFrame(1, new byte[58], true));

        // When / Then
        assertThat(packet.isAckOnly()).isFalse();
    }

    @Test
    void emptyPacketIsNotAckOnly() throws Exception {
        // Given
        QuicPacket packet = new ShortHeaderPacket(Version.getDefault());

        // When / Then
        assertThat(packet.isAckOnly()).isFalse();
    }
    //endregion
}
