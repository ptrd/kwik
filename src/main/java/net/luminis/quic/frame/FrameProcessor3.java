package net.luminis.quic.frame;

import net.luminis.quic.packet.QuicPacket;

import java.time.Instant;

public interface FrameProcessor3 {

    void process(QuicFrame frame, QuicPacket packet, Instant timeReceived);

    void process(AckFrame ackFrame, QuicPacket packet, Instant timeReceived);

    void process(ConnectionCloseFrame connectionCloseFrame, QuicPacket packet, Instant timeReceived);

    void process(CryptoFrame cryptoFrame, QuicPacket packet, Instant timeReceived);

    void process(HandshakeDoneFrame handshakeDoneFrame, QuicPacket packet, Instant timeReceived);

    void process(MaxDataFrame maxDataFrame, QuicPacket packet, Instant timeReceived);

    void process(MaxStreamDataFrame maxStreamDataFrame, QuicPacket packet, Instant timeReceived);

    void process(MaxStreamsFrame maxStreamsFrame, QuicPacket packet, Instant timeReceived);

    void process(NewConnectionIdFrame newConnectionIdFrame, QuicPacket packet, Instant timeReceived);

    void process(NewTokenFrame newTokenFrame, QuicPacket packet, Instant timeReceived);

    void process(PathChallengeFrame pathChallengeFrame, QuicPacket packet, Instant timeReceived);

    void process(Padding paddingFrames, QuicPacket packet, Instant timeReceived);

    void process(PingFrame pingFrame, QuicPacket packet, Instant timeReceived);

    void process(RetireConnectionIdFrame retireConnectionIdFrame, QuicPacket packet, Instant timeReceived);

    void process(StreamFrame streamFrame, QuicPacket packet, Instant timeReceived);

}
