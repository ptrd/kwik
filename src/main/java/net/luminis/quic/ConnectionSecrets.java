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

public class ConnectionSecrets {

    private final Version quicVersion;

    enum NodeRole {
        Client,
        Server
    }

    // https://tools.ietf.org/html/draft-ietf-quic-tls-23#section-5.2
    public static final byte[] STATIC_SALT_DRAFT_23 = new byte[] {
            (byte) 0xc3, (byte) 0xee, (byte) 0xf7, (byte) 0x12, (byte) 0xc7, (byte) 0x2e, (byte) 0xbb, (byte) 0x5a,
            (byte) 0x11, (byte) 0xa7, (byte) 0xd2, (byte) 0x43, (byte) 0x2b, (byte) 0xb4, (byte) 0x63, (byte) 0x65,
            (byte) 0xbe, (byte) 0xf9, (byte) 0xf5, (byte) 0x02 };

    private Logger log;

    private Keys[] clientSecrets = new Keys[EncryptionLevel.values().length];
    private Keys[] serverSecrets = new Keys[EncryptionLevel.values().length];

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

        byte[] initialSalt = STATIC_SALT_DRAFT_23;
        byte[] initialSecret = hkdf.extract(initialSalt, destConnectionId);

        log.secret("Initial secret", initialSecret);

        clientSecrets[EncryptionLevel.Initial.ordinal()] = new Keys(quicVersion, initialSecret, NodeRole.Client, log);
        serverSecrets[EncryptionLevel.Initial.ordinal()] = new Keys(quicVersion, initialSecret, NodeRole.Server, log);
    }

    public synchronized void computeEarlySecrets(TlsState tlsState) {
        Keys zeroRttSecrets = new Keys(quicVersion, NodeRole.Client, log);
        zeroRttSecrets.computeZeroRttKeys(tlsState);
        clientSecrets[EncryptionLevel.ZeroRTT.ordinal()] = zeroRttSecrets;
    }

    public synchronized void computeHandshakeSecrets(TlsState tlsState) {
        Keys handshakeSecrets = new Keys(quicVersion, NodeRole.Client, log);
        handshakeSecrets.computeHandshakeKeys(tlsState);
        clientSecrets[EncryptionLevel.Handshake.ordinal()] = handshakeSecrets;

        handshakeSecrets = new Keys(quicVersion, NodeRole.Server, log);
        handshakeSecrets.computeHandshakeKeys(tlsState);
        serverSecrets[EncryptionLevel.Handshake.ordinal()] = handshakeSecrets;
    }

    public synchronized void computeApplicationSecrets(TlsState tlsState) {
        Keys applicationSecrets = new Keys(quicVersion, NodeRole.Client, log);
        applicationSecrets.computeApplicationKeys(tlsState);
        clientSecrets[EncryptionLevel.App.ordinal()] = applicationSecrets;

        applicationSecrets = new Keys(quicVersion, NodeRole.Server, log);
        applicationSecrets.computeApplicationKeys(tlsState);
        serverSecrets[EncryptionLevel.App.ordinal()] = applicationSecrets;
    }

    public synchronized Keys getClientSecrets(EncryptionLevel encryptionLevel) {
        return clientSecrets[encryptionLevel.ordinal()];
    }

    public synchronized Keys getServerSecrets(EncryptionLevel encryptionLevel) {
        return serverSecrets[encryptionLevel.ordinal()];
    }
}
