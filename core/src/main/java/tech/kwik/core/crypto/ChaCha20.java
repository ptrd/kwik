/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.crypto;

import at.favre.lib.hkdf.HKDF;
import tech.kwik.core.impl.DecryptionException;
import tech.kwik.core.impl.QuicRuntimeException;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
 * "QUIC can use any of the cipher suites defined in [TLS13] with the exception of TLS_AES_128_CCM_8_SHA256."
 * https://www.rfc-editor.org/rfc/rfc8446.html#appendix-B.4
 * "AEAD_CHACHA20_POLY1305 is defined in [RFC8439]."
 */
public class ChaCha20 extends BaseAeadImpl {

    public ChaCha20(Version quicVersion, Role nodeRole, boolean initial, byte[] secret, byte[] hp, Logger log) {
        super(quicVersion, nodeRole, initial, secret, hp, log);
    }

    @Override
    protected short getHashLength() {
        return 32;
    }

    @Override
    protected short getKeyLength() {
        return 32;
    }

    @Override
    protected HKDF getHKDF() {
        return HKDF.fromHmacSha256();
    }

    @Override
    public Cipher getHeaderProtectionCipher() {
        if (hpCipher == null) {
            try {
                hpCipher = Cipher.getInstance("ChaCha20");
            } catch (NoSuchAlgorithmException e) {
                // Inappropriate runtime environment
                throw new QuicRuntimeException(e);
            } catch (NoSuchPaddingException e) {
                // Programming error
                throw new RuntimeException();
            }
        }
        return hpCipher;
    }

    @Override
    public SecretKeySpec getKeySpec() {
        if (keySpec == null) {
            keySpec = new SecretKeySpec(key, "ChaCha20-Poly1305");
        }
        return keySpec;
    }

    @Override
    public Cipher getCipher() {
        if (cipher == null) {
            try {
                cipher = Cipher.getInstance("ChaCha20-Poly1305");
            }
            catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                // Inappropriate runtime environment
                throw new QuicRuntimeException(e);
            }
        }
        return cipher;
    }

    @Override
    public byte[] aeadEncrypt(byte[] associatedData, byte[] message, byte[] nonce) {
        try {
            Cipher aeadCipher = getCipher();
            IvParameterSpec chacha20poly1305Spec = new IvParameterSpec(nonce);
            Key key = getKeySpec();
            aeadCipher.init(Cipher.ENCRYPT_MODE, key, chacha20poly1305Spec);
            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        }
        catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
    }

    @Override
    public byte[] aeadDecrypt(byte[] associatedData, byte[] message, byte[] nonce) throws DecryptionException {
        try {
            Cipher aeadCipher = getCipher();
            IvParameterSpec chacha20poly1305Spec = new IvParameterSpec(nonce);
            Key key = getKeySpec();
            aeadCipher.init(Cipher.DECRYPT_MODE, key, chacha20poly1305Spec);
            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        }
        catch (AEADBadTagException decryptError) {
            throw new DecryptionException();
        }
        catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
    }

    @Override
    public byte[] createHeaderProtectionMask(byte[] sample) {
        try {
            Cipher hpCipher = Cipher.getInstance("ChaCha20");
            byte[] nonce = Arrays.copyOfRange(sample, 4, 16);
            byte[] counterBytes = new byte[4];
            counterBytes[0] = sample[3];
            counterBytes[1] = sample[2];
            counterBytes[2] = sample[1];
            counterBytes[3] = sample[0];
            int counter = ByteBuffer.wrap(counterBytes).getInt();
            ChaCha20ParameterSpec chaCha20ParameterSpec = new ChaCha20ParameterSpec(nonce, counter);
            SecretKeySpec key = new SecretKeySpec(hp, "ChaCha20");
            hpCipher.init(Cipher.ENCRYPT_MODE, key, chaCha20ParameterSpec);
            byte[] mask = hpCipher.doFinal(new byte[]{ 0, 0, 0, 0, 0 });
            return mask;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Inappropriate runtime environment
            throw new QuicRuntimeException(e);
        } catch (InvalidKeyException e) {
            // Programming error
            throw new RuntimeException();
        } catch (BadPaddingException e) {
            throw new RuntimeException();
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException();
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException();
        }
    }
}

