package net.luminis.quic;

// https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-20.1
public class TransportError extends QuicError {

    private final QuicConstants.TransportErrorCode transportErrorCode;

    public TransportError(QuicConstants.TransportErrorCode transportErrorCode) {
        this.transportErrorCode = transportErrorCode;
    }

    public QuicConstants.TransportErrorCode getTransportErrorCode() {
        return transportErrorCode;
    }
}
