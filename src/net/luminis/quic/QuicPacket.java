package net.luminis.quic;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

abstract public class QuicPacket {

    byte[] encodeVariableLengthInteger(int length) {
        if (length <= 63)
            return new byte[] { (byte) length };
        else if (length <= 16383) {
            ByteBuffer buffer = ByteBuffer.allocate(2);
            buffer.putShort((short) length);
            byte[] bytes = buffer.array();
            bytes[0] = (byte) (bytes[0] | (byte) 0x40);
            return bytes;
        }
        else {
            // TODO
            throw new RuntimeException("NIY");
        }
    }

    byte[] encodePacketNumber(int number) {
        if (number <= 0x7f)
            return new byte[] { (byte) number };
        else {
            // TODO
            throw new RuntimeException("NIY");
        }
    }

    byte[] encryptPayload(byte[] message, byte[] associatedData, int packetNumber, ConnectionSecrets secrets) {

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
        // "The nonce, N, is formed by combining the packet
        //   protection IV with the packet number.  The 64 bits of the
        //   reconstructed QUIC packet number in network byte order are left-
        //   padded with zeros to the size of the IV.  The exclusive OR of the
        //   padded packet number and the IV forms the AEAD nonce"
        ByteBuffer nonceInput = ByteBuffer.allocate(secrets.clientWriteIV.length);
        for (int i = 0; i < nonceInput.capacity() - 8; i++)
            nonceInput.put((byte) 0x00);
        nonceInput.putLong((long) packetNumber);

        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ secrets.clientWriteIV[i++]);

        try {
            SecretKeySpec secretKey = new SecretKeySpec(secrets.clientWriteKey, "AES");
            // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
            // "Prior to establishing a shared secret, packets are protected with AEAD_AES_128_GCM"
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);   // https://tools.ietf.org/html/rfc5116  5.3
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            aeadCipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            aeadCipher.updateAAD(associatedData);
            byte[] cipherText = aeadCipher.doFinal(message);
            return cipherText;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Inappropriate runtime environment
            throw new QuicRuntimeException(e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
    }

    byte[] createProtectedPacketNumber(byte[] ciphertext, int packetNumber, ConnectionSecrets secrets) {

        //int sampleOffset = 6 + initialConnectionId.length + sourceConnectionId.length + 2 /* length(payload_length) */ + 4;
        int sampleOffset = 3;    // TODO
        byte[] sample = new byte[16];
        System.arraycopy(ciphertext, sampleOffset, sample,0,16);
        byte[] encryptedPn = encryptAesCtr(secrets.clientPn, sample, new byte[] { (byte) packetNumber });   // TODO: if pn > 1 byte
        return encryptedPn;
    }

    byte[] encryptAesCtr(byte[] key, byte[] initVector, byte[] value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value);
            return encrypted;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Inappropriate runtime environment
            throw new QuicRuntimeException(e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
    }
}
