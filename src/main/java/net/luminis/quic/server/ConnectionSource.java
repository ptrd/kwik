package net.luminis.quic.server;

import java.util.Arrays;

public class ConnectionSource {

    private final byte[] dcid;

    public ConnectionSource(byte[] dcid) {
        this.dcid = dcid;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(dcid);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ConnectionSource) {
            return Arrays.equals(this.dcid, ((ConnectionSource) obj).dcid);
        }
        else {
            return false;
        }
    }
}
