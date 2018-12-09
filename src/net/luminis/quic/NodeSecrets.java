package net.luminis.quic;

import static net.luminis.quic.ConnectionSecrets.NodeRole.Client;

public class NodeSecrets {

    final byte[] initialNodeSecret;
    final byte[] writeKey;
    final byte[] writeIV;
    final byte[] pn;

    public NodeSecrets(byte[] initialSecret, ConnectionSecrets.NodeRole nodeRole, Logger log) {

        initialNodeSecret = Crypto.hkdfExpandLabel(initialSecret, nodeRole == Client? "client in": "server in", "", (short) 32);
        log.debug(nodeRole + " initial secret", initialNodeSecret);

        // https://tools.ietf.org/html/rfc8446#section-7.3
        writeKey = Crypto.hkdfExpandLabel(initialNodeSecret, "key", "", (short) 16);
        log.debug(nodeRole + " key", writeKey);

        writeIV = Crypto.hkdfExpandLabel(initialNodeSecret, "iv", "", (short) 12);
        log.debug(nodeRole + " iv", writeIV);

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.1: 'to derive a packet number protection key (the "pn" label")'
        pn = Crypto.hkdfExpandLabel(initialNodeSecret, "pn", "", (short) 16);
        log.debug(nodeRole + " pn", pn);
    }
}
