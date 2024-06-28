module tech.kwik.core {
    requires tech.kwik.agent15;
    requires at.favre.lib.hkdf;

    exports net.luminis.quic;
    exports net.luminis.quic.concurrent;
    exports net.luminis.quic.generic;
    exports net.luminis.quic.server;
    exports net.luminis.quic.log;
    exports net.luminis.quic.common to tech.kwik.qlog;
    exports net.luminis.quic.frame to tech.kwik.qlog;
    exports net.luminis.quic.packet to tech.kwik.qlog;
    exports net.luminis.quic.util to tech.kwik.qlog;
}
