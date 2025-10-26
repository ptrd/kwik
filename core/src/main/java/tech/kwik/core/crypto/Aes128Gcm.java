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

    public Aes128Gcm(Version quicVersion, Role nodeRole, boolean initial, byte[] secret, byte[] hp, Logger log) {
        super(quicVersion, nodeRole, initial, secret, hp, log);
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
    public SecretKeySpec getKeySpec() {
        if (keySpec == null) {
            keySpec = new SecretKeySpec(key, "AES");
        }
        return keySpec;
    }

    @Override
    public Cipher getCipher() {
        if (cipher == null) {
            try {
                // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
                // "Prior to establishing a shared secret, packets are protected with AEAD_AES_128_GCM"
                String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
                cipher = Cipher.getInstance(AES_GCM_NOPADDING);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                // Inappropriate runtime environment
                throw new QuicRuntimeException(e);
            }
        }
        return cipher;
    }

    @Override
    public byte[] aeadEncrypt(byte[] associatedData, byte[] message, byte[] nonce) {
        Cipher aeadCipher = getCipher();
        SecretKeySpec secretKey = getKeySpec();
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
        SecretKeySpec secretKey = getKeySpec();
        Cipher aeadCipher = getCipher();
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
