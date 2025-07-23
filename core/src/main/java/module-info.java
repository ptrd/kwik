module tech.kwik.core {
    requires tech.kwik.agent15;
    requires at.favre.lib.hkdf;
    requires io.whitfin.siphash;
    requires java.management;
    requires java.compiler;

    exports tech.kwik.core;
    exports tech.kwik.core.concurrent;
    exports tech.kwik.core.generic;
    exports tech.kwik.core.server;
    exports tech.kwik.core.log;
    exports tech.kwik.core.common to tech.kwik.qlog;
    exports tech.kwik.core.frame to tech.kwik.qlog;
    exports tech.kwik.core.packet to tech.kwik.qlog;
    exports tech.kwik.core.util to tech.kwik.qlog;
}
