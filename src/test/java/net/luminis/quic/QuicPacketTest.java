package net.luminis.quic;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

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
}