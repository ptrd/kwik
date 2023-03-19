/*
 * Copyright © 2020, 2021, 2022, 2023 Peter Doornbosch
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

import net.luminis.quic.DecryptionException;
import net.luminis.quic.QuicRuntimeException;
import net.luminis.quic.Role;
import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class Chacha20Keys extends BaseKeysImpl {

    public Chacha20Keys(Version quicVersion, Role server, Logger log) {
        super(quicVersion, server, log);
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
    public SecretKeySpec getWriteKeySpec() {
        if (writeKeySpec == null) {
            writeKeySpec = new SecretKeySpec(writeKey, "ChaCha20-Poly1305");
        }
        return writeKeySpec;
    }

    @Override
    public Cipher getWriteCipher() {
        if (writeCipher == null) {
            try {
                writeCipher = Cipher.getInstance("ChaCha20-Poly1305");
            }
            catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                // Inappropriate runtime environment
                throw new QuicRuntimeException(e);
            }
        }
        return writeCipher;
    }

    @Override
    public byte[] aeadEncrypt(byte[] associatedData, byte[] message, byte[] nonce) {
        try {
            Cipher aeadCipher = getWriteCipher();
            IvParameterSpec chacha20poly1305Spec = new IvParameterSpec(nonce);
            Key key = getWriteKeySpec();
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
            Cipher aeadCipher = getWriteCipher();
            IvParameterSpec chacha20poly1305Spec = new IvParameterSpec(nonce);
            Key key = getWriteKeySpec();
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

