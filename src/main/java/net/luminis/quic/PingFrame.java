package net.luminis.quic;


import java.nio.ByteBuffer;

public class PingFrame extends QuicFrame {

    public PingFrame parse(ByteBuffer buffer, Logger log) {
        buffer.get();
        return this;
    }

    @Override
    byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public String toString() {
        return "PingFrame[]";
    }
}
