/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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
import net.luminis.quic.core.EncryptionLevel;
import net.luminis.quic.core.Role;
import net.luminis.quic.core.Version;
import net.luminis.quic.core.VersionHolder;
import net.luminis.quic.log.Logger;
import net.luminis.tls.*;
import net.luminis.tls.util.ByteUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

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
    private Logger log;
    private byte[] clientRandom;
    private Aead[] clientSecrets = new Aead[EncryptionLevel.values().length];
    private Aead[] serverSecrets = new Aead[EncryptionLevel.values().length];
    private boolean writeSecretsToFile;
    private Path wiresharkSecretsFile;
    private byte[] originalDestinationConnectionId;
    private boolean[] discarded = new boolean[EncryptionLevel.values().length];


    public ConnectionSecrets(VersionHolder quicVersion, Role role, Path wiresharksecrets, Logger log) {
        this.quicVersion = quicVersion;
        this.ownRole = role;
        this.log = log;

        if (wiresharksecrets != null) {
            wiresharkSecretsFile = wiresharksecrets;
            try {
                Files.deleteIfExists(wiresharkSecretsFile);
                Files.createFile(wiresharkSecretsFile);
                writeSecretsToFile = true;
            } catch (IOException e) {
                log.error("Initializing (creating/truncating) secrets file '" + wiresharkSecretsFile + "' failed", e);
            }
        }
    }

    /**
     * Generate the initial secrets
     *
     * @param destConnectionId
     */
    public synchronized void computeInitialKeys(byte[] destConnectionId) {
        this.originalDestinationConnectionId = destConnectionId;
        Version actualVersion = quicVersion.getVersion();

        byte[] initialSecret = computeInitialSecret(actualVersion);
        log.secret("Initial secret", initialSecret);

        // https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
        // "Initial packets use AEAD_AES_128_GCM with keys derived from the Destination Connection ID field of the first
        //  Initial packet sent by the client; "
        clientSecrets[EncryptionLevel.Initial.ordinal()] = new Aes128Gcm(actualVersion, initialSecret, Role.Client, log);
        serverSecrets[EncryptionLevel.Initial.ordinal()] = new Aes128Gcm(actualVersion, initialSecret, Role.Server, log);
    }

    /**
     * (Re)generates the keys for the initial peer secrets based on the given version. This is sometimes used during
     * version negotiation, when a packet with the "old" (original) version needs to be decoded.
     * @param version
     * @return
     */
    public Aead getInitialPeerSecretsForVersion(Version version) {
        return new Aes128Gcm(version, computeInitialSecret(version), ownRole.other(), log);
    }

    private byte[] computeInitialSecret(Version actualVersion) {
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
        // "The hash function for HKDF when deriving initial secrets and keys is SHA-256"
        HKDF hkdf = HKDF.fromHmacSha256();

        byte[] initialSalt = actualVersion.isV1() ? STATIC_SALT_V1 : actualVersion.isV2() ? STATIC_SALT_V2 : STATIC_SALT_DRAFT_29;
        return hkdf.extract(initialSalt, originalDestinationConnectionId);
    }

    public void recomputeInitialKeys() {
        computeInitialKeys(originalDestinationConnectionId);
    }

    public synchronized void computeEarlySecrets(TrafficSecrets secrets, TlsConstants.CipherSuite cipherSuite, Version originalVersion) {
        // Note: for server role, at this point, the current version may be different from the original version (when a different version than the original has been negotiated)
        createKeys(EncryptionLevel.ZeroRTT, cipherSuite, originalVersion);

        byte[] earlySecret = secrets.getClientEarlyTrafficSecret();
        clientSecrets[EncryptionLevel.ZeroRTT.ordinal()].computeKeys(earlySecret);
    }

    private void createKeys(EncryptionLevel level, TlsConstants.CipherSuite selectedCipherSuite, Version version) {
        Aead clientHandshakeSecrets;
        Aead serverHandshakeSecrets;

        if (selectedCipherSuite == TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256) {
            clientHandshakeSecrets = new Aes128Gcm(version, Role.Client, log);
            serverHandshakeSecrets = new Aes128Gcm(version, Role.Server, log);
        }
        else if (selectedCipherSuite == TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384) {
            clientHandshakeSecrets = new Aes256Gcm(version, Role.Client, log);
            serverHandshakeSecrets = new Aes256Gcm(version, Role.Server, log);
        }
        else if (selectedCipherSuite == TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256) {
            clientHandshakeSecrets = new ChaCha20(version, Role.Client, log);
            serverHandshakeSecrets = new ChaCha20(version, Role.Server, log);
        }
        else {
            throw new IllegalStateException("unsupported cipher suite " + selectedCipherSuite);
        }
        clientSecrets[level.ordinal()] = clientHandshakeSecrets;
        if (level != EncryptionLevel.ZeroRTT) {  // Server does not use write keys for 0-RTT
            serverSecrets[level.ordinal()] = serverHandshakeSecrets;
        }

        // Keys for peer and keys for self must be able to signal each other of a key update.
        clientHandshakeSecrets.setPeerAead(serverHandshakeSecrets);
        serverHandshakeSecrets.setPeerAead(clientHandshakeSecrets);
    }

    public synchronized void computeHandshakeSecrets(TrafficSecrets secrets, TlsConstants.CipherSuite selectedCipherSuite) {
        this.selectedCipherSuite = selectedCipherSuite;
        createKeys(EncryptionLevel.Handshake, selectedCipherSuite, quicVersion.getVersion());

        byte[] clientHandshakeTrafficSecret = secrets.getClientHandshakeTrafficSecret();
        log.secret("ClientHandshakeTrafficSecret: ", clientHandshakeTrafficSecret);
        clientSecrets[EncryptionLevel.Handshake.ordinal()].computeKeys(clientHandshakeTrafficSecret);

        byte[] serverHandshakeTrafficSecret = secrets.getServerHandshakeTrafficSecret();
        log.secret("ServerHandshakeTrafficSecret: ", serverHandshakeTrafficSecret);
        serverSecrets[EncryptionLevel.Handshake.ordinal()].computeKeys(serverHandshakeTrafficSecret);

        if (writeSecretsToFile) {
            appendToFile("HANDSHAKE_TRAFFIC_SECRET", EncryptionLevel.Handshake);
        }
    }

    public synchronized void computeApplicationSecrets(TrafficSecrets secrets) {
        createKeys(EncryptionLevel.App, selectedCipherSuite, quicVersion.getVersion());

        byte[] clientApplicationTrafficSecret = secrets.getClientApplicationTrafficSecret();
        log.secret("ClientApplicationTrafficSecret: ", clientApplicationTrafficSecret);
        clientSecrets[EncryptionLevel.App.ordinal()].computeKeys(clientApplicationTrafficSecret);

        byte[] serverApplicationTrafficSecret = secrets.getServerApplicationTrafficSecret();
        log.secret("ServerApplicationTrafficSecret: ", serverApplicationTrafficSecret);
        serverSecrets[EncryptionLevel.App.ordinal()].computeKeys(serverApplicationTrafficSecret);

        if (writeSecretsToFile) {
            appendToFile("TRAFFIC_SECRET_0", EncryptionLevel.App);
        }
    }

    private void appendToFile(String label, EncryptionLevel level) {
        List<String> content = new ArrayList<>();
        content.add("CLIENT_" + label + " "
                + ByteUtils.bytesToHex(clientRandom) + " "
                + ByteUtils.bytesToHex(clientSecrets[level.ordinal()].getTrafficSecret()));
        content.add("SERVER_" + label + " "
                + ByteUtils.bytesToHex(clientRandom) + " "
                + ByteUtils.bytesToHex(serverSecrets[level.ordinal()].getTrafficSecret()));

        try {
            Files.write(wiresharkSecretsFile, content, StandardOpenOption.APPEND);
        } catch (IOException e) {
            log.error("Writing secrets to file '" + wiresharkSecretsFile + "' failed", e);
            writeSecretsToFile = false;
        }
    }

    public void setClientRandom(byte[] clientRandom) {
        this.clientRandom = clientRandom;
    }

    public synchronized Aead getClientAead(EncryptionLevel encryptionLevel) throws MissingKeysException {
        return checkNotNull(clientSecrets[encryptionLevel.ordinal()], encryptionLevel);
    }

    public synchronized Aead getServerAead(EncryptionLevel encryptionLevel) throws MissingKeysException {
        return checkNotNull(serverSecrets[encryptionLevel.ordinal()], encryptionLevel);
    }

    public synchronized Aead getPeerAead(EncryptionLevel encryptionLevel) throws MissingKeysException {
        Aead aead = (ownRole == Role.Client) ? serverSecrets[encryptionLevel.ordinal()] : clientSecrets[encryptionLevel.ordinal()];
        return checkNotNull(aead, encryptionLevel);
    }

    public synchronized Aead getOwnAead(EncryptionLevel encryptionLevel) throws MissingKeysException {
        Aead aead = (ownRole == Role.Client) ? clientSecrets[encryptionLevel.ordinal()] : serverSecrets[encryptionLevel.ordinal()];
        return checkNotNull(aead, encryptionLevel);
    }

    private Aead checkNotNull(Aead aead, EncryptionLevel encryptionLevel) throws MissingKeysException {
        if (aead == null) {
            throw new MissingKeysException(encryptionLevel, discarded[encryptionLevel.ordinal()]);
        }
        else {
            return aead;
        }
    }

    public void discardKeys(EncryptionLevel encryptionLevel) {
        discarded[encryptionLevel.ordinal()] = true;
        clientSecrets[encryptionLevel.ordinal()] = null;
        serverSecrets[encryptionLevel.ordinal()] = null;
    }
}
