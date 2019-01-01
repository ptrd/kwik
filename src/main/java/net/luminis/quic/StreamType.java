package net.luminis.quic;

enum StreamType {

    ClientInitiatedBidirectional(0, "CIB"),
    ServerInitiatedBidirectional(1, "SIB"),
    ClientInitiatedUnidirectional(2, "CIU"),
    ServerInitiatedUnidirectional(3, "SIU"),
    ;

    public final int value;
    public final String abbrev;

    StreamType(int value, String abbrev) {
        this.value = value;
        this.abbrev = abbrev;
    }
}
