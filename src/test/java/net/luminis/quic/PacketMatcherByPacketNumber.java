package net.luminis.quic;

import net.luminis.quic.packet.QuicPacket;
import org.mockito.ArgumentMatcher;

class PacketMatcherByPacketNumber implements ArgumentMatcher<QuicPacket> {

    private int packetNumber;

    PacketMatcherByPacketNumber(int packetNumber) {
        this.packetNumber = packetNumber;
    }

    @Override
    public boolean matches(QuicPacket quicPacket) {
        return quicPacket.getPacketNumber() == packetNumber;
    }
}
