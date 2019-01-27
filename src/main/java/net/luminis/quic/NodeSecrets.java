/*
 * Copyright © 2019 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package net.luminis.quic;

import net.luminis.tls.TlsState;


import static net.luminis.quic.ConnectionSecrets.NodeRole.Client;
import static net.luminis.quic.ConnectionSecrets.NodeRole.Server;

public class NodeSecrets {

    private final ConnectionSecrets.NodeRole nodeRole;
    private final Logger log;
    private final Version quicVersion;

    private byte[] writeKey;
    private byte[] writeIV;
    private byte[] pn;
    private byte[] hp;

    public NodeSecrets(Version quicVersion, ConnectionSecrets.NodeRole nodeRole, Logger log) {
        this.nodeRole = nodeRole;
        this.log = log;
        this.quicVersion = quicVersion;
    }

    public NodeSecrets(Version quicVersion, byte[] initialSecret, ConnectionSecrets.NodeRole nodeRole, Logger log) {
        this.nodeRole = nodeRole;
        this.log = log;
        this.quicVersion = quicVersion;

        byte[] initialNodeSecret = Crypto.hkdfExpandLabel(quicVersion, initialSecret, nodeRole == Client? "client in": "server in", "", (short) 32);
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

        String prefix;
        if (quicVersion.atLeast(Version.IETF_draft_17)) {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1
            // "The current encryption level secret and the label "quic key" are
            //   input to the KDF to produce the AEAD key; the label "quic iv" is used
            //   to derive the IV, see Section 5.3.  The header protection key uses
            //   the "quic hp" label, see Section 5.4).  Using these labels provides
            //   key separation between QUIC and TLS, see Section 9.4."
            prefix = "quic ";
        }
        else {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.1
            // "The keys used for packet protection are computed from the TLS secrets
            //   using the method described in Section 7.3 of [TLS13]), except that
            //   the label for HKDF-Expand-Label uses the prefix "quic " rather than
            //   "tls13 ""
            prefix = "";
        }


        // https://tools.ietf.org/html/rfc8446#section-7.3
        writeKey = Crypto.hkdfExpandLabel(quicVersion, secret, prefix + "key", "", (short) 16);
        log.secret(nodeRole + " key", writeKey);

        writeIV = Crypto.hkdfExpandLabel(quicVersion, secret, prefix + "iv", "", (short) 12);
        log.secret(nodeRole + " iv", writeIV);

        if (quicVersion.atLeast(Version.IETF_draft_17)) {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1
            // "The header protection key uses the "quic hp" label"
            hp = Crypto.hkdfExpandLabel(quicVersion, secret, prefix + "hp", "", (short) 16);
            log.secret(nodeRole + " hp", hp);
        }
        else {
            // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.1: 'to derive a packet number protection key (the "pn" label")'
            pn = Crypto.hkdfExpandLabel(quicVersion, secret, prefix + "pn", "", (short) 16);
            log.secret(nodeRole + " pn", pn);
        }
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

    public byte[] getHp() {
        return hp;
    }
}
