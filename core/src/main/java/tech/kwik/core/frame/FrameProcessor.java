package tech.kwik.core.frame;

import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;

/**
 * Processor that is able to process all frame types.
 */
public interface FrameProcessor {

    void process(AckFrame ackFrame, QuicPacket packet, PacketMetaData metaData);

    void process(ConnectionCloseFrame connectionCloseFrame, QuicPacket packet, PacketMetaData metaData);

    void process(CryptoFrame cryptoFrame, QuicPacket packet, PacketMetaData metaData);

    void process(DataBlockedFrame dataBlockedFrame, QuicPacket packet, PacketMetaData metaData);

    void process(DatagramFrame datagramFrame, QuicPacket packet, PacketMetaData metaData);

    void process(HandshakeDoneFrame handshakeDoneFrame, QuicPacket packet, PacketMetaData metaData);

    void process(MaxDataFrame maxDataFrame, QuicPacket packet, PacketMetaData metaData);

    void process(MaxStreamDataFrame maxStreamDataFrame, QuicPacket packet, PacketMetaData metaData);

    void process(MaxStreamsFrame maxStreamsFrame, QuicPacket packet, PacketMetaData metaData);

    void process(NewConnectionIdFrame newConnectionIdFrame, QuicPacket packet, PacketMetaData metaData);

    void process(NewTokenFrame newTokenFrame, QuicPacket packet, PacketMetaData metaData);

    void process(Padding paddingFrame, QuicPacket packet, PacketMetaData metaData);

    void process(PathChallengeFrame pathChallengeFrame, QuicPacket packet, PacketMetaData metaData);

    void process(PathResponseFrame pathResponseFrame, QuicPacket packet, PacketMetaData metaData);

    void process(PingFrame pingFrame, QuicPacket packet, PacketMetaData metaData);

    void process(ResetStreamFrame resetStreamFrame, QuicPacket packet, PacketMetaData metaData);

    void process(RetireConnectionIdFrame retireConnectionIdFrame, QuicPacket packet, PacketMetaData metaData);

    void process(StopSendingFrame stopSendingFrame, QuicPacket packet, PacketMetaData metaData);

    void process(StreamFrame streamFrame, QuicPacket packet, PacketMetaData metaData);

    void process(StreamDataBlockedFrame streamDataBlockedFrame, QuicPacket packet, PacketMetaData metaData);

    void process(StreamsBlockedFrame streamsBlockedFrame, QuicPacket packet, PacketMetaData metaData);
}
