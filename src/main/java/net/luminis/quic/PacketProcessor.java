package net.luminis.quic;

public interface PacketProcessor {

    void process(InitialPacket packet);

    void process(LongHeaderPacket packet);

    void process(ShortHeaderPacket packet);

    void process(VersionNegotationPacket packet);

    void process(HandshakePacket packet);
}
