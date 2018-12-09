package net.luminis.quic;

public class ProtocolError extends RuntimeException {

    public ProtocolError(String message) {
        super(message);
    }
}
