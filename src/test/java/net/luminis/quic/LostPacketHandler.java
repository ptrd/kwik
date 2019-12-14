package net.luminis.quic;

import net.luminis.quic.packet.QuicPacket;

interface LostPacketHandler {

    void process(QuicPacket lostPacket);
}
