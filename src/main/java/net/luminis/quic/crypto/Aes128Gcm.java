package net.luminis.quic.crypto;

import at.favre.lib.crypto.HKDF;
import net.luminis.quic.core.DecryptionException;
import net.luminis.quic.core.QuicRuntimeException;
import net.luminis.quic.core.Role;
import net.luminis.quic.core.Version;
import net.luminis.quic.log.Logger;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
 * "QUIC can use any of the cipher suites defined in [TLS13] with the exception of TLS_AES_128_CCM_8_SHA256."
 * https://www.rfc-editor.org/rfc/rfc8446.html#appendix-B.4
 * "The corresponding AEAD algorithms AEAD_AES_128_GCM (...) are defined in [RFC5116]."
 */
public class Aes128Gcm extends BaseAeadImpl {

    public Aes128Gcm(Version quicVersion, Role nodeRole, Logger log) {
        super(quicVersion, nodeRole, log);
    }

    public Aes128Gcm(Version quicVersion, byte[] initialSecret, Role nodeRole, Logger log) {
        super(quicVersion, initialSecret, nodeRole, log);
    }

    @Override
    protected short getKeyLength() {
        return 16;
    }

    @Override
    protected short getHashLength() {
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

    @Override
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

    @Override
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

    @Override
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

    @Override
    public byte[] aeadEncrypt(byte[] associatedData, byte[] message, byte[] nonce) {
        Cipher aeadCipher = getWriteCipher();
        SecretKeySpec secretKey = getWriteKeySpec();
        try {
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);   // https://tools.ietf.org/html/rfc5116#section-5.3: "the tag length t is 16"
            aeadCipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException |
                 BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
    }

    @Override
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
}
