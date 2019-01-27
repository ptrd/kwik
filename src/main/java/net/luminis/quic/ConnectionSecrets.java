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
import net.luminis.tls.TlsState;

public class ConnectionSecrets {

    private final Version quicVersion;

    enum NodeRole {
        Client,
        Server
    }

    // https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.2
    public static final byte[] STATIC_SALT = new byte[]{
            (byte) 0x9c, (byte) 0x10, (byte) 0x8f, (byte) 0x98,
            (byte) 0x52, (byte) 0x0a, (byte) 0x5c, (byte) 0x5c,
            (byte) 0x32, (byte) 0x96, (byte) 0x8e, (byte) 0x95,
            (byte) 0x0e, (byte) 0x8a, (byte) 0x2c, (byte) 0x5f,
            (byte) 0xe0, (byte) 0x6d, (byte) 0x6c, (byte) 0x38};

    private Logger log;

    private NodeSecrets[] clientSecrets = new NodeSecrets[EncryptionLevel.values().length];
    private NodeSecrets[] serverSecrets = new NodeSecrets[EncryptionLevel.values().length];

    public ConnectionSecrets(Version quicVersion, Logger log) {
        this.quicVersion = quicVersion;
        this.log = log;
    }

    /**
     * Generate the initial secrets
     *
     * @param destConnectionId
     */
    public synchronized void computeInitialKeys(byte[] destConnectionId) {

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.2:
        // "The hash function for HKDF when deriving initial secrets and keys is SHA-256"
        HKDF hkdf = HKDF.fromHmacSha256();

        byte[] initialSecret = hkdf.extract(STATIC_SALT, destConnectionId);
        log.secret("Initial secret", initialSecret);

        clientSecrets[EncryptionLevel.Initial.ordinal()] = new NodeSecrets(quicVersion, initialSecret, NodeRole.Client, log);
        serverSecrets[EncryptionLevel.Initial.ordinal()] = new NodeSecrets(quicVersion, initialSecret, NodeRole.Server, log);
    }

    public synchronized void computeHandshakeSecrets(TlsState tlsState) {
        NodeSecrets handshakeSecrets = new NodeSecrets(quicVersion, NodeRole.Client, log);
        handshakeSecrets.computeHandshakeKeys(tlsState);
        clientSecrets[EncryptionLevel.Handshake.ordinal()] = handshakeSecrets;

        handshakeSecrets = new NodeSecrets(quicVersion, NodeRole.Server, log);
        handshakeSecrets.computeHandshakeKeys(tlsState);
        serverSecrets[EncryptionLevel.Handshake.ordinal()] = handshakeSecrets;
    }

    public synchronized void computeApplicationSecrets(TlsState tlsState) {
        NodeSecrets applicationSecrets = new NodeSecrets(quicVersion, NodeRole.Client, log);
        applicationSecrets.computeApplicationKeys(tlsState);
        clientSecrets[EncryptionLevel.App.ordinal()] = applicationSecrets;

        applicationSecrets = new NodeSecrets(quicVersion, NodeRole.Server, log);
        applicationSecrets.computeApplicationKeys(tlsState);
        serverSecrets[EncryptionLevel.App.ordinal()] = applicationSecrets;
    }

    public synchronized NodeSecrets getClientSecrets(EncryptionLevel encryptionLevel) {
        return clientSecrets[encryptionLevel.ordinal()];
    }

    public synchronized NodeSecrets getServerSecrets(EncryptionLevel encryptionLevel) {
        return serverSecrets[encryptionLevel.ordinal()];
    }
}
