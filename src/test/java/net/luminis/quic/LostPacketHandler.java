package net.luminis.quic;

interface LostPacketHandler {

    void process(QuicPacket lostPacket);
}
