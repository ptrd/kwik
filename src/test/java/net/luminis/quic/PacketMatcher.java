package net.luminis.quic;

import org.mockito.ArgumentMatcher;

class PacketMatcher implements ArgumentMatcher<QuicPacket> {

    private int packetNumber;

    PacketMatcher(int packetNumber) {
        this.packetNumber = packetNumber;
    }

    @Override
    public boolean matches(QuicPacket quicPacket) {
        return quicPacket.getPacketNumber() == packetNumber;
    }
}
