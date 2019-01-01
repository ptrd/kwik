package net.luminis.quic;

public interface FrameProcessor {

    void process(QuicFrame ackFrame, EncryptionLevel encryptionLevel);

}
