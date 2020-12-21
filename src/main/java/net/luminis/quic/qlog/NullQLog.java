package net.luminis.quic.qlog;

import net.luminis.quic.packet.QuicPacket;

import java.time.Instant;


public class NullQLog implements QLog {

    @Override
    public void emitConnectionCreatedEvent(Instant created) {}

    @Override
    public void emitPacketSentEvent(QuicPacket packet, Instant sent) {}

    @Override
    public void emitPacketReceivedEvent(QuicPacket packet, Instant received) {}

    @Override
    public void emitConnectionTerminatedEvent() {}

    @Override
    public void emitCongestionControlMetrics(long congestionWindow, long bytesInFlight) {}
}
