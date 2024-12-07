/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
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
package net.luminis.quic.crypto;

import at.favre.lib.hkdf.HKDF;
import net.luminis.quic.common.EncryptionLevel;
import net.luminis.quic.impl.Role;
import net.luminis.quic.impl.Version;
import net.luminis.quic.impl.VersionHolder;
import net.luminis.quic.log.Logger;
import net.luminis.quic.util.Bytes;
import net.luminis.quic.util.TriFunction;
import net.luminis.tls.TlsConstants;
import net.luminis.tls.engine.TrafficSecrets;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReferenceArray;

public class ConnectionSecrets {

    private TlsConstants.CipherSuite selectedCipherSuite;

    // https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.2
    public static final byte[] STATIC_SALT_DRAFT_29 = new byte[] {
            (byte) 0xaf, (byte) 0xbf, (byte) 0xec, (byte) 0x28, (byte) 0x99, (byte) 0x93, (byte) 0xd2, (byte) 0x4c,
            (byte) 0x9e, (byte) 0x97, (byte) 0x86, (byte) 0xf1, (byte) 0x9c, (byte) 0x61, (byte) 0x11, (byte) 0xe0,
            (byte) 0x43, (byte) 0x90, (byte) 0xa8, (byte) 0x99 };

    // https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
    // "initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
    public static final byte[] STATIC_SALT_V1 = new byte[] {
            (byte) 0x38, (byte) 0x76, (byte) 0x2c, (byte) 0xf7, (byte) 0xf5, (byte) 0x59, (byte) 0x34, (byte) 0xb3,
            (byte) 0x4d, (byte) 0x17, (byte) 0x9a, (byte) 0xe6, (byte) 0xa4, (byte) 0xc8, (byte) 0x0c, (byte) 0xad,
            (byte) 0xcc, (byte) 0xbb, (byte) 0x7f, (byte) 0x0a };

    // https://www.rfc-editor.org/rfc/rfc9369.html#name-initial-salt
    // "The salt used to derive Initial keys in Section 5.2 of [QUIC-TLS] changes to:
    //  initial_salt = 0x0dede3def700a6db819381be6e269dcbf9bd2ed9"
    public static final byte[] STATIC_SALT_V2 = new byte[] {
            (byte) 0x0d, (byte) 0xed, (byte) 0xe3, (byte) 0xde, (byte) 0xf7, (byte) 0x00, (byte) 0xa6, (byte) 0xdb,
            (byte) 0x81, (byte) 0x93, (byte) 0x81, (byte) 0xbe, (byte) 0x6e, (byte) 0x26, (byte) 0x9d, (byte) 0xcb,
            (byte) 0xf9, (byte) 0xbd, (byte) 0x2e, (byte) 0xd9 };

    private final VersionHolder quicVersion;
    private final Role ownRole;
    private final Logger log;
    private volatile byte[] clientRandom;
    private final AtomicReferenceArray<Aead> clientSecrets = new AtomicReferenceArray<>(EncryptionLevel.values().length);
    private final AtomicReferenceArray<Aead> serverSecrets = new AtomicReferenceArray<>(EncryptionLevel.values().length);
    private volatile Aead originalClientInitialSecret;
    private final boolean writeSecretsToFile;
    private final Path wiresharkSecretsFile;
    private volatile byte[] originalDestinationConnectionId;
    private final AtomicBoolean[] discarded = new AtomicBoolean[EncryptionLevel.values().length];


    public ConnectionSecrets(VersionHolder quicVersion, Role role, Path wiresharksecrets, Logger log) {
        this.quicVersion = quicVersion;
        this.ownRole = role;
        this.log = log;
        Arrays.fill(discarded, new AtomicBoolean(false));

        boolean mustWriteSecretsToFile = false;
        if (wiresharksecrets != null) {
            wiresharkSecretsFile = wiresharksecrets;
            try {
                Files.deleteIfExists(wiresharkSecretsFile);
                Files.createFile(wiresharkSecretsFile);
                mustWriteSecretsToFile = true;
            }
            catch (IOException e) {
                log.error("Initializing (creating/truncating) secrets file '" + wiresharkSecretsFile + "' failed", e);
            }
        }
        else {
            wiresharkSecretsFile = null;
        }
        writeSecretsToFile = mustWriteSecretsToFile;
    }

    /**
     * Generate the initial secrets and configure AEAD algorithm accordingly.
     *
     * @param destConnectionId
     */
    public void computeInitialKeys(byte[] destConnectionId) {
        this.originalDestinationConnectionId = destConnectionId;
        Version actualVersion = quicVersion.getVersion();

        byte[] initialSecret = computeInitialSecret(actualVersion);
        log.secret("Initial secret", initialSecret);

        // https://www.rfc-editor.org/rfc/rfc9001.html#section-5
        // "Initial packets use AEAD_AES_128_GCM with keys derived from the Destination Connection ID field of the first
        //  Initial packet sent by the client; "
        createKeys(EncryptionLevel.Initial, TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256, actualVersion, true, initialSecret, initialSecret);
    }

    /**
     * Recompute the initial secrets based on a new destination connection id. This only happens when the server sends
     * a Retry packet; a Retry packet contains a new (server) source destination id, which must be used by the client as
     * the new destination connection id.
     * This method keeps the original (client) initial keys that must be used for decoding client packets without the
     * (retry) token (which can happen if the retry is lost or otherwise not received in time by the client).
     * @param destConnectionId
     */
    public void recomputeInitialKeys(byte[] destConnectionId) {
        originalClientInitialSecret = clientSecrets.get(EncryptionLevel.Initial.ordinal());
        this.originalDestinationConnectionId = destConnectionId;
        computeInitialKeys(destConnectionId);
    }

    /**
     * (Re)generates the keys for the initial peer secrets based on the given version. This is sometimes used during
     * version negotiation, when a packet with the "old" (original) version needs to be decoded.
     * @param version
     * @return
     */
    public Aead getInitialPeerSecretsForVersion(Version version) {
        return new Aes128Gcm(version, ownRole.other(), true, computeInitialSecret(version), null, log);
    }

    private byte[] computeInitialSecret(Version actualVersion) {
        // https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2
        // "This secret is determined by using HKDF-Extract (see Section 2.2 of [HKDF]) with a salt of
        //  0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a and the input keying material (IKM) of the Destination Connection ID
        //  field. This produces an intermediate pseudorandom key (PRK) that is used to derive two separate secrets for
        //  sending and receiving."
        // "The hash function for HKDF when deriving initial secrets and keys is SHA-256"
        HKDF hkdf = HKDF.fromHmacSha256();

        byte[] initialSalt = actualVersion.isV1() ? STATIC_SALT_V1 : actualVersion.isV2() ? STATIC_SALT_V2 : STATIC_SALT_DRAFT_29;
        return hkdf.extract(initialSalt, originalDestinationConnectionId);
    }

    public void recomputeInitialKeys() {
        computeInitialKeys(originalDestinationConnectionId);
    }

    public void computeEarlySecrets(TrafficSecrets secrets, TlsConstants.CipherSuite cipherSuite, Version originalVersion) {
        // Note: for server role, at this point, the current version may be different from the original version (when a different version than the original has been negotiated)
        byte[] earlySecret = secrets.getClientEarlyTrafficSecret();
        createKeys(EncryptionLevel.ZeroRTT, cipherSuite, originalVersion, false, earlySecret, null);
    }

    private void createKeys(EncryptionLevel level, TlsConstants.CipherSuite selectedCipherSuite, Version version,
                            boolean initial, byte[] clientHandshakeTrafficSecret, byte[] serverHandshakeTrafficSecret) {
        TriFunction<Role, byte[], byte[], Aead> aeadFactory;

        if (selectedCipherSuite == TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256) {
            aeadFactory = (role, secret, hp) -> new Aes128Gcm(version, role, initial, secret, hp, log);
        }
        else if (selectedCipherSuite == TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384) {
            aeadFactory = (role, secret, hp) -> new Aes256Gcm(version, role, initial, secret, hp, log);
        }
        else if (selectedCipherSuite == TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256) {
            aeadFactory = (role, secret, hp) -> new ChaCha20(version, role, initial, secret, hp, log);
        }
        else {
            throw new IllegalStateException("unsupported cipher suite " + selectedCipherSuite);
        }

        Aead clientAead = null;
        Aead serverAead = null;
        if (clientHandshakeTrafficSecret != null) {
            clientAead = aeadFactory.apply(Role.Client, clientHandshakeTrafficSecret, null);
        }
        if (serverHandshakeTrafficSecret != null) {
            serverAead = aeadFactory.apply(Role.Server, serverHandshakeTrafficSecret, null);
        }

        if (level == EncryptionLevel.App) {
            assert (clientAead != null) && (serverAead != null);
            // Wrap Aead with KeyUpdateSupport to support key updates (only allowed on 1-RTT/App level)
            clientAead = new KeyUpdateSupport(clientAead, Role.Client, aeadFactory, log);
            serverAead = new KeyUpdateSupport(serverAead, Role.Server, aeadFactory, log);
            // Keys for peer and keys for self must be able to signal each other of a key update.
            clientAead.setPeerAead(serverAead);
            serverAead.setPeerAead(clientAead);
        }

        clientSecrets.set(level.ordinal(), clientAead);
        serverSecrets.set(level.ordinal(), serverAead);
    }

    public void computeHandshakeSecrets(TrafficSecrets tlsTrafficSecrets, TlsConstants.CipherSuite selectedCipherSuite) {
        this.selectedCipherSuite = selectedCipherSuite;

        byte[] clientHandshakeTrafficSecret = tlsTrafficSecrets.getClientHandshakeTrafficSecret();
        log.secret("ClientHandshakeTrafficSecret: ", clientHandshakeTrafficSecret);
        byte[] serverHandshakeTrafficSecret = tlsTrafficSecrets.getServerHandshakeTrafficSecret();
        log.secret("ServerHandshakeTrafficSecret: ", serverHandshakeTrafficSecret);

        createKeys(EncryptionLevel.Handshake, selectedCipherSuite, quicVersion.getVersion(), false, clientHandshakeTrafficSecret, serverHandshakeTrafficSecret);

        if (writeSecretsToFile) {
            appendToFile("HANDSHAKE_TRAFFIC_SECRET", EncryptionLevel.Handshake);
        }
    }

    public void computeApplicationSecrets(TrafficSecrets secrets) {
        byte[] clientApplicationTrafficSecret = secrets.getClientApplicationTrafficSecret();
        log.secret("ClientApplicationTrafficSecret: ", clientApplicationTrafficSecret);
        byte[] serverApplicationTrafficSecret = secrets.getServerApplicationTrafficSecret();
        log.secret("ServerApplicationTrafficSecret: ", serverApplicationTrafficSecret);

        createKeys(EncryptionLevel.App, selectedCipherSuite, quicVersion.getVersion(), false, clientApplicationTrafficSecret, serverApplicationTrafficSecret);

        if (writeSecretsToFile) {
            appendToFile("TRAFFIC_SECRET_0", EncryptionLevel.App);
        }
    }

    private void appendToFile(String label, EncryptionLevel level) {
        List<String> content = new ArrayList<>();
        content.add("CLIENT_" + label + " "
                + Bytes.bytesToHex(clientRandom) + " "
                + Bytes.bytesToHex(clientSecrets.get(level.ordinal()).getTrafficSecret()));
        content.add("SERVER_" + label + " "
                + Bytes.bytesToHex(clientRandom) + " "
                + Bytes.bytesToHex(serverSecrets.get(level.ordinal()).getTrafficSecret()));

        try {
            Files.write(wiresharkSecretsFile, content, StandardOpenOption.APPEND);
        }
        catch (IOException e) {
            log.error("Writing secrets to file '" + wiresharkSecretsFile + "' failed", e);
        }
    }

    public void setClientRandom(byte[] clientRandom) {
        this.clientRandom = clientRandom;
    }

    public Aead getClientAead(EncryptionLevel encryptionLevel) throws MissingKeysException {
        return checkNotNull(clientSecrets.get(encryptionLevel.ordinal()), encryptionLevel);
    }

    public Aead getServerAead(EncryptionLevel encryptionLevel) throws MissingKeysException {
        return checkNotNull(serverSecrets.get(encryptionLevel.ordinal()), encryptionLevel);
    }

    public Aead getPeerAead(EncryptionLevel encryptionLevel) throws MissingKeysException {
        int index = encryptionLevel.ordinal();
        Aead aead = (ownRole == Role.Client) ? serverSecrets.get(index) : clientSecrets.get(index);
        return checkNotNull(aead, encryptionLevel);
    }

    public Aead getOwnAead(EncryptionLevel encryptionLevel) throws MissingKeysException {
        int index = encryptionLevel.ordinal();
        Aead aead = (ownRole == Role.Client) ? clientSecrets.get(index) : serverSecrets.get(index);
        return checkNotNull(aead, encryptionLevel);
    }

    /**
     * Returns the initial secrets based on the original (server) destination connection id.
     * This differs from the current initial secrets when the server has sent a Retry packet.
     * The original (client) initial keys must be used for decoding client packets without the
     * (retry) token (which can happen if the retry is lost or otherwise not received in time by the client).
     */
    public Aead getOriginalClientInitialAead() {
        if (originalClientInitialSecret != null) {
            return originalClientInitialSecret;
        }
        else {
            return clientSecrets.get(EncryptionLevel.Initial.ordinal());
        }
    }

    private Aead checkNotNull(Aead aead, EncryptionLevel encryptionLevel) throws MissingKeysException {
        if (aead == null) {
            throw new MissingKeysException(encryptionLevel, discarded[encryptionLevel.ordinal()].get());
        }
        else {
            return aead;
        }
    }

    public void discardKeys(EncryptionLevel encryptionLevel) {
        discarded[encryptionLevel.ordinal()].set(true);
        clientSecrets.set(encryptionLevel.ordinal(), null);
        serverSecrets.set(encryptionLevel.ordinal(), null);
    }
}
