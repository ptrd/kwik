package net.luminis.quic;

import net.luminis.tls.TlsState;


import static net.luminis.quic.ConnectionSecrets.NodeRole.Client;
import static net.luminis.quic.ConnectionSecrets.NodeRole.Server;

public class NodeSecrets {

    private final ConnectionSecrets.NodeRole nodeRole;
    private final Logger log;

    private byte[] writeKey;
    private byte[] writeIV;
    private byte[] pn;

    public NodeSecrets(ConnectionSecrets.NodeRole nodeRole, Logger log) {
        this.nodeRole = nodeRole;
        this.log = log;
    }

    public NodeSecrets(byte[] initialSecret, ConnectionSecrets.NodeRole nodeRole, Logger log) {
        this.nodeRole = nodeRole;
        this.log = log;

        byte[] initialNodeSecret = Crypto.hkdfExpandLabel(initialSecret, nodeRole == Client? "client in": "server in", "", (short) 32);
        log.secret(nodeRole + " initial secret", initialNodeSecret);

        computeKeys(initialNodeSecret);
    }

    public synchronized void computeHandshakeKeys(TlsState tlsState) {
        if (nodeRole == Client) {
            byte[] clientHandshakeTrafficSecret = tlsState.getClientHandshakeTrafficSecret();
            log.secret("ClientHandshakeTrafficSecret: ", clientHandshakeTrafficSecret);
            computeKeys(clientHandshakeTrafficSecret);
        }
        if (nodeRole == Server) {
            byte[] serverHandshakeTrafficSecret = tlsState.getServerHandshakeTrafficSecret();
            log.secret("ServerHandshakeTrafficSecret: ", serverHandshakeTrafficSecret);
            computeKeys(serverHandshakeTrafficSecret);
        }
    }

    public synchronized void computeApplicationKeys(TlsState tlsState) {
        if (nodeRole == Client) {
            byte[] clientApplicationTrafficSecret = tlsState.getClientApplicationTrafficSecret();
            log.secret("ClientApplicationTrafficSecret: ", clientApplicationTrafficSecret);
            computeKeys(clientApplicationTrafficSecret);
        }
        if (nodeRole == Server) {
            byte[] serverApplicationTrafficSecret = tlsState.getServerApplicationTrafficSecret();
            log.secret("Got new serverApplicationTrafficSecret from TLS (recomputing secrets): ", serverApplicationTrafficSecret);
            computeKeys(serverApplicationTrafficSecret);
        }
    }

    private void computeKeys(byte[] secret) {
        // https://tools.ietf.org/html/rfc8446#section-7.3
        writeKey = Crypto.hkdfExpandLabel(secret, "key", "", (short) 16);
        log.secret(nodeRole + " key", writeKey);

        writeIV = Crypto.hkdfExpandLabel(secret, "iv", "", (short) 12);
        log.secret(nodeRole + " iv", writeIV);

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.1: 'to derive a packet number protection key (the "pn" label")'
        pn = Crypto.hkdfExpandLabel(secret, "pn", "", (short) 16);
        log.secret(nodeRole + " pn", pn);
    }

    public byte[] getWriteKey() {
        return writeKey;
    }

    public byte[] getWriteIV() {
        return writeIV;
    }

    public byte[] getPn() {
        return pn;
    }
}
