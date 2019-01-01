package net.luminis.quic;


public class QuicRuntimeException extends RuntimeException {

    public QuicRuntimeException(Exception cause) {
        super(cause);
    }
}
