package net.luminis.quic;


public class ProtocolError extends RuntimeException {

    public ProtocolError(String message) {
        super(message);
    }

    public ProtocolError(String message, Throwable cause) {
        super(message, cause);
    }
}
