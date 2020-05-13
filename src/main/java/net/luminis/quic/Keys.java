/*
 * Copyright © 2019, 2020 Peter Doornbosch
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


import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

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
    private Cipher hpCipher;
    private SecretKeySpec writeKeySpec;
    private Cipher writeCipher;


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

    public synchronized void computeZeroRttKeys(TlsState tlsState) {
        byte[] earlySecret = tlsState.getClientEarlyTrafficSecret();
        computeKeys(earlySecret);
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
        if (writeKeySpec == null) {
            writeKeySpec = new SecretKeySpec(writeKey, "AES");
        }
        return writeKeySpec;
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
}
