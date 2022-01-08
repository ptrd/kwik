/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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

import at.favre.lib.crypto.HKDF;
import net.luminis.quic.DecryptionException;
import net.luminis.quic.QuicRuntimeException;
import net.luminis.quic.Role;
import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.tls.TrafficSecrets;


import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static net.luminis.quic.Role.Client;
import static net.luminis.quic.Role.Server;

public class Keys {

    public static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");

    private final Role nodeRole;
    private final Logger log;
    private final Version quicVersion;

    private byte[] trafficSecret;
    private byte[] newApplicationTrafficSecret;
    protected byte[] writeKey;
    protected byte[] newKey;
    protected byte[] writeIV;
    protected byte[] newIV;
    protected byte[] hp;
    protected Cipher hpCipher;
    protected SecretKeySpec writeKeySpec;
    protected SecretKeySpec newWriteKeySpec;
    protected Cipher writeCipher;
    private int keyUpdateCounter = 0;
    private boolean possibleKeyUpdateInProgresss = false;
    private volatile Keys peerKeys;

    public Keys(Version quicVersion, Role nodeRole, Logger log) {
        this.nodeRole = nodeRole;
        this.log = log;
        this.quicVersion = quicVersion;
    }

    public Keys(Version quicVersion, byte[] initialSecret, Role nodeRole, Logger log) {
        this.nodeRole = nodeRole;
        this.log = log;
        this.quicVersion = quicVersion;

        byte[] initialNodeSecret = hkdfExpandLabel(quicVersion, initialSecret, nodeRole == Client? "client in": "server in", "", (short) 32);
        log.secret(nodeRole + " initial secret", initialNodeSecret);

        computeKeys(initialNodeSecret, true, true);
    }

    public synchronized void computeZeroRttKeys(TrafficSecrets secrets) {
        byte[] earlySecret = secrets.getClientEarlyTrafficSecret();
        computeKeys(earlySecret, true, true);
    }

    public synchronized void computeHandshakeKeys(TrafficSecrets secrets) {
        if (nodeRole == Client) {
            trafficSecret = secrets.getClientHandshakeTrafficSecret();
            log.secret("ClientHandshakeTrafficSecret: ", trafficSecret);
            computeKeys(trafficSecret, true, true);
        }
        if (nodeRole == Server) {
            trafficSecret = secrets.getServerHandshakeTrafficSecret();
            log.secret("ServerHandshakeTrafficSecret: ", trafficSecret);
            computeKeys(trafficSecret, true, true);
        }
    }

    public synchronized void computeApplicationKeys(TrafficSecrets secrets) {
        if (nodeRole == Client) {
            trafficSecret = secrets.getClientApplicationTrafficSecret();
            log.secret("ClientApplicationTrafficSecret: ", trafficSecret);
            computeKeys(trafficSecret, true, true);
        }
        if (nodeRole == Server) {
            trafficSecret = secrets.getServerApplicationTrafficSecret();
            log.secret("Got new serverApplicationTrafficSecret from TLS (recomputing secrets): ", trafficSecret);
            computeKeys(trafficSecret, true, true);
        }
    }

    /**
     * Compute new keys. Note that depending on the role of this Keys object, computing new keys concerns updating
     * the write secrets (role that initiates the key update) or the read secrets (role that responds to the key update).
     * @param selfInitiated        true when this role initiated the key update, so updating write secrets.
     */
    public synchronized void computeKeyUpdate(boolean selfInitiated) {
        newApplicationTrafficSecret = hkdfExpandLabel(quicVersion, trafficSecret, "quic ku", "", (short) 32);
        log.secret("Updated ApplicationTrafficSecret (" + (selfInitiated? "self":"peer") + "): ", newApplicationTrafficSecret);
        computeKeys(newApplicationTrafficSecret, false, selfInitiated);
        if (selfInitiated) {
            // If updating this Keys object was self initiated, the new keys can be installed immediately.
            trafficSecret = newApplicationTrafficSecret;
            keyUpdateCounter++;
            newApplicationTrafficSecret = null;
        }
        // Else, updating this Keys object was initiated by receiving a packet with different key phase, and the new keys
        // can only be installed permanently if the decryption of the packet (that introduced the new key phase) has succeeded.
    }

    /**
     * Confirm that, if a key update was in progress, it has been successful and thus the new keys can (and should) be
     * used for decrypting all incoming packets.
     */
    public synchronized void confirmKeyUpdateIfInProgress() {
        if (possibleKeyUpdateInProgresss) {
            log.info("Installing updated keys (initiated by peer)");
            trafficSecret = newApplicationTrafficSecret;
            writeKey = newKey;
            writeKeySpec = null;
            writeIV = newIV;
            keyUpdateCounter++;
            newApplicationTrafficSecret = null;
            possibleKeyUpdateInProgresss = false;
            newKey = null;
            newIV = null;
            checkPeerKeys();
        }
    }

    /**
     * In case keys are updated, check if the peer keys are already updated too (which depends on who initiated the
     * key update).
     */
    private void checkPeerKeys() {
        if (peerKeys.keyUpdateCounter < keyUpdateCounter) {
            log.debug("Keys out of sync; updating keys for peer");
            peerKeys.computeKeyUpdate(true);
        }
    }

    /**
     * Confirm that, if a key update was in progress, it has been unsuccessful and thus the new keys should not be
     * used for decrypting all incoming packets.
     */
    public synchronized void cancelKeyUpdateIfInProgress() {
        if (possibleKeyUpdateInProgresss) {
            log.info("Discarding updated keys (initiated by peer)");
            newApplicationTrafficSecret = null;
            possibleKeyUpdateInProgresss = false;
            newKey = null;
            newIV = null;
        }
    }

    private void computeKeys(byte[] secret, boolean includeHP, boolean replaceKeys) {

        String prefix;
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1
        // "The current encryption level secret and the label "quic key" are
        //   input to the KDF to produce the AEAD key; the label "quic iv" is used
        //   to derive the IV, see Section 5.3.  The header protection key uses
        //   the "quic hp" label, see Section 5.4).  Using these labels provides
        //   key separation between QUIC and TLS, see Section 9.4."
        prefix = "quic ";

        // https://tools.ietf.org/html/rfc8446#section-7.3
        byte[] key = hkdfExpandLabel(quicVersion, secret, prefix + "key", "", getKeyLength());
        if (replaceKeys) {
            writeKey = key;
            writeKeySpec = null;
        }
        else {
            newKey = key;
            newWriteKeySpec = null;
        }
        log.secret(nodeRole + " key", key);

        byte[] iv = hkdfExpandLabel(quicVersion, secret, prefix + "iv", "", (short) 12);
        if (replaceKeys) {
            writeIV = iv;
        }
        else {
            newIV = iv;
        }
        log.secret(nodeRole + " iv", iv);

        if (includeHP) {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1
            // "The header protection key uses the "quic hp" label"
            hp = hkdfExpandLabel(quicVersion, secret, prefix + "hp", "", getKeyLength());
            log.secret(nodeRole + " hp", hp);
        }
    }

    protected short getKeyLength() {
        return 16;
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
        if (possibleKeyUpdateInProgresss) {
            return newKey;
        }
        return writeKey;
    }

    public byte[] getWriteIV() {
        if (possibleKeyUpdateInProgresss) {
            return newIV;
        }
        return writeIV;
    }

    public byte[] getHp() {
        return hp;
    }

    public Cipher getHeaderProtectionCipher() {
        if (hpCipher == null) {
            try {
                // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.3
                // "AEAD_AES_128_GCM and AEAD_AES_128_CCM use 128-bit AES [AES] in electronic code-book (ECB) mode."
                hpCipher = Cipher.getInstance("AES/ECB/NoPadding");
                SecretKeySpec keySpec = new SecretKeySpec(getHp(), "AES");
                hpCipher.init(Cipher.ENCRYPT_MODE, keySpec);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                // Inappropriate runtime environment
                throw new QuicRuntimeException(e);
            } catch (InvalidKeyException e) {
                // Programming error
                throw new RuntimeException();
            }
        }
        return hpCipher;
    }

    public SecretKeySpec getWriteKeySpec() {
        if (possibleKeyUpdateInProgresss) {
            if (newWriteKeySpec == null) {
                newWriteKeySpec = new SecretKeySpec(newKey, "AES");
            }
            return newWriteKeySpec;
        }
        else {
            if (writeKeySpec == null) {
                writeKeySpec = new SecretKeySpec(writeKey, "AES");
            }
            return writeKeySpec;
        }
    }

    public Cipher getWriteCipher() {
        if (writeCipher == null) {
            try {
                // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
                // "Prior to establishing a shared secret, packets are protected with AEAD_AES_128_GCM"
                String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
                writeCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                // Inappropriate runtime environment
                throw new QuicRuntimeException(e);
            }
        }
        return writeCipher;
    }

    public byte[] aeadEncrypt(byte[] associatedData, byte[] message, byte[] nonce) {
        Cipher aeadCipher = getWriteCipher();
        SecretKeySpec secretKey = getWriteKeySpec();
        try {
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);   // https://tools.ietf.org/html/rfc5116#section-5.3: "the tag length t is 16"
            aeadCipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
    }

    public byte[] aeadDecrypt(byte[] associatedData, byte[] message, byte[] nonce) throws DecryptionException {
        if (message.length <= 16) {
            // https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
            // "These cipher suites have a 16-byte authentication tag and produce an output 16 bytes larger than their input."
            throw new DecryptionException("ciphertext must be longer than 16 bytes");
        }
        SecretKeySpec secretKey = getWriteKeySpec();
        Cipher aeadCipher = getWriteCipher();
        try {
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);   // https://tools.ietf.org/html/rfc5116#section-5.3: "the tag length t is 16"
            aeadCipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        } catch (AEADBadTagException decryptError) {
            throw new DecryptionException();
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
    }

    public byte[] createHeaderProtectionMask(byte[] sample) {
        Cipher hpCipher = getHeaderProtectionCipher();
        byte[] mask;
        try {
            mask = hpCipher.doFinal(sample);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
        return mask;
    }

    public short getKeyPhase() {
        return (short) (keyUpdateCounter % 2);
    }

    /**
     * Check whether the key phase carried by a received packet still matches the current key phase; if not, compute
     * new keys (to be used for decryption). Note that the changed key phase can also be caused by packet corruption,
     * so it is not yet sure whether a key update is really in progress (this will be sure when decryption of the packet
     * failed or succeeded).
     * @param keyPhaseBit
     */
    public void checkKeyPhase(short keyPhaseBit) {
        if ((keyUpdateCounter % 2) != keyPhaseBit) {
            if (newKey == null) {
                computeKeyUpdate(false);
                log.secret("Computed new (updated) key", newKey);
                log.secret("Computed new (updated) iv", newIV);
            }
            log.info("Received key phase does not match current => possible key update in progress");
            possibleKeyUpdateInProgresss = true;
        }
    }

    void setPeerKeys(Keys peerKeys) {
        this.peerKeys = peerKeys;
    }
}
