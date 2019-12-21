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

import at.favre.lib.crypto.HKDF;
import net.luminis.quic.log.Logger;
import net.luminis.tls.TlsState;


import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import static net.luminis.quic.ConnectionSecrets.NodeRole.Client;
import static net.luminis.quic.ConnectionSecrets.NodeRole.Server;

public class Keys {

    public static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");

    private final ConnectionSecrets.NodeRole nodeRole;
    private final Logger log;
    private final Version quicVersion;

    private byte[] trafficSecret;
    private byte[] writeKey;
    private byte[] writeIV;
    private byte[] pn;
    private byte[] hp;

    public Keys(Version quicVersion, ConnectionSecrets.NodeRole nodeRole, Logger log) {
        this.nodeRole = nodeRole;
        this.log = log;
        this.quicVersion = quicVersion;
    }

    public Keys(Version quicVersion, byte[] initialSecret, ConnectionSecrets.NodeRole nodeRole, Logger log) {
        this.nodeRole = nodeRole;
        this.log = log;
        this.quicVersion = quicVersion;

        byte[] initialNodeSecret = hkdfExpandLabel(quicVersion, initialSecret, nodeRole == Client? "client in": "server in", "", (short) 32);
        log.secret(nodeRole + " initial secret", initialNodeSecret);

        computeKeys(initialNodeSecret);
    }

    public synchronized void computeHandshakeKeys(TlsState tlsState) {
        if (nodeRole == Client) {
            trafficSecret = tlsState.getClientHandshakeTrafficSecret();
            log.secret("ClientHandshakeTrafficSecret: ", trafficSecret);
            computeKeys(trafficSecret);
        }
        if (nodeRole == Server) {
            trafficSecret = tlsState.getServerHandshakeTrafficSecret();
            log.secret("ServerHandshakeTrafficSecret: ", trafficSecret);
            computeKeys(trafficSecret);
        }
    }

    public synchronized void computeApplicationKeys(TlsState tlsState) {
        if (nodeRole == Client) {
            trafficSecret = tlsState.getClientApplicationTrafficSecret();
            log.secret("ClientApplicationTrafficSecret: ", trafficSecret);
            computeKeys(trafficSecret);
        }
        if (nodeRole == Server) {
            trafficSecret = tlsState.getServerApplicationTrafficSecret();
            log.secret("Got new serverApplicationTrafficSecret from TLS (recomputing secrets): ", trafficSecret);
            computeKeys(trafficSecret);
        }
    }

    private void computeKeys(byte[] secret) {

        String prefix;
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1
        // "The current encryption level secret and the label "quic key" are
        //   input to the KDF to produce the AEAD key; the label "quic iv" is used
        //   to derive the IV, see Section 5.3.  The header protection key uses
        //   the "quic hp" label, see Section 5.4).  Using these labels provides
        //   key separation between QUIC and TLS, see Section 9.4."
        prefix = "quic ";


        // https://tools.ietf.org/html/rfc8446#section-7.3
        writeKey = hkdfExpandLabel(quicVersion, secret, prefix + "key", "", (short) 16);
        log.secret(nodeRole + " key", writeKey);

        writeIV = hkdfExpandLabel(quicVersion, secret, prefix + "iv", "", (short) 12);
        log.secret(nodeRole + " iv", writeIV);

        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1
        // "The header protection key uses the "quic hp" label"
        hp = hkdfExpandLabel(quicVersion, secret, prefix + "hp", "", (short) 16);
        log.secret(nodeRole + " hp", hp);
    }

    // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
    static byte[] hkdfExpandLabel(Version quicVersion, byte[] secret, String label, String context, short length) {

        byte[] prefix;
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1:
        // "The keys used for packet protection are computed from the TLS secrets using the KDF provided by TLS."
        prefix = "tls13 ".getBytes(ISO_8859_1);

        ByteBuffer hkdfLabel = ByteBuffer.allocate(2 + 1 + prefix.length + label.getBytes(ISO_8859_1).length + 1 + context.getBytes(ISO_8859_1).length);
        hkdfLabel.putShort(length);
        hkdfLabel.put((byte) (prefix.length + label.getBytes().length));
        hkdfLabel.put(prefix);
        hkdfLabel.put(label.getBytes(ISO_8859_1));
        hkdfLabel.put((byte) (context.getBytes(ISO_8859_1).length));
        hkdfLabel.put(context.getBytes(ISO_8859_1));
        HKDF hkdf = HKDF.fromHmacSha256();
        return hkdf.expand(secret, hkdfLabel.array(), length);
    }

    public byte[] getTrafficSecret() {
        return trafficSecret;
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
