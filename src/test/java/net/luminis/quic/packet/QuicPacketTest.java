package net.luminis.quic.packet;

import net.luminis.quic.packet.QuicPacket;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

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

}
