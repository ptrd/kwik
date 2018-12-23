package net.luminis.quic;

import net.luminis.tls.TlsState;


import static net.luminis.quic.ConnectionSecrets.NodeRole.Client;
import static net.luminis.quic.ConnectionSecrets.NodeRole.Server;

public class NodeSecrets {

    private final ConnectionSecrets.NodeRole nodeRole;
    private final Logger log;

    byte[] initialNodeSecret;
    byte[] writeKey;
    byte[] writeIV;
    byte[] pn;

    public NodeSecrets(byte[] initialSecret, ConnectionSecrets.NodeRole nodeRole, Logger log) {
        this.nodeRole = nodeRole;
        this.log = log;

        initialNodeSecret = Crypto.hkdfExpandLabel(initialSecret, nodeRole == Client? "client in": "server in", "", (short) 32);
        log.debug(nodeRole + " initial secret", initialNodeSecret);

        computeKeys(initialNodeSecret);
    }

    public void recompute(TlsState tlsState) {
        if (nodeRole == Client) {
            byte[] clientHandshakeTrafficSecret = tlsState.getClientHandshakeTrafficSecret();
            log.debug("Got new clientHandshakeTrafficSecret from TLS (recomputing secrets): ", clientHandshakeTrafficSecret);
            computeKeys(clientHandshakeTrafficSecret);
        }
        if (nodeRole == Server) {
            byte[] serverHandshakeTrafficSecret = tlsState.getServerHandshakeTrafficSecret();
            log.debug("Got new serverHandshakeTrafficSecret from TLS (recomputing secrets): ", serverHandshakeTrafficSecret);
            computeKeys(serverHandshakeTrafficSecret);
        }
    }

    private void computeKeys(byte[] secret) {
        // https://tools.ietf.org/html/rfc8446#section-7.3
        writeKey = Crypto.hkdfExpandLabel(secret, "key", "", (short) 16);
        log.debug(nodeRole + " key", writeKey);

        writeIV = Crypto.hkdfExpandLabel(secret, "iv", "", (short) 12);
        log.debug(nodeRole + " iv", writeIV);

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.1: 'to derive a packet number protection key (the "pn" label")'
        pn = Crypto.hkdfExpandLabel(secret, "pn", "", (short) 16);
        log.debug(nodeRole + " pn", pn);
    }
}
