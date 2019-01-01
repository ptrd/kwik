package net.luminis.quic;

import net.luminis.tls.TlsState;

public class QuicTlsState extends TlsState {

    public QuicTlsState() {
        super("quic ");
    }
}
