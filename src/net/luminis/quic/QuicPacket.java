package net.luminis.quic;

import net.luminis.tls.TlsState;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

abstract public class QuicPacket {

    protected Version quicVersion;
    protected int packetNumber;
    protected List<QuicFrame> frames;

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

    byte[] encryptPayload(byte[] message, byte[] associatedData, int packetNumber, NodeSecrets secrets) {

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
        // "The nonce, N, is formed by combining the packet
        //   protection IV with the packet number.  The 64 bits of the
        //   reconstructed QUIC packet number in network byte order are left-
        //   padded with zeros to the size of the IV.  The exclusive OR of the
        //   padded packet number and the IV forms the AEAD nonce"
        ByteBuffer nonceInput = ByteBuffer.allocate(secrets.writeIV.length);
        for (int i = 0; i < nonceInput.capacity() - 8; i++)
            nonceInput.put((byte) 0x00);
        nonceInput.putLong((long) packetNumber);

        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ secrets.writeIV[i++]);

        try {
            SecretKeySpec secretKey = new SecretKeySpec(secrets.writeKey, "AES");
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

    byte[] decryptPayload(byte[] message, byte[] associatedData, int packetNumber, NodeSecrets secrets) {
        ByteBuffer nonceInput = ByteBuffer.allocate(12);
        nonceInput.putInt(0);
        nonceInput.putLong((long) packetNumber);

        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ secrets.writeIV[i++]);

        try {
            SecretKeySpec secretKey = new SecretKeySpec(secrets.writeKey, "AES");
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);   // https://tools.ietf.org/html/rfc5116  5.3
            aeadCipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Inappropriate runtime environment
            throw new QuicRuntimeException(e);
        } catch (AEADBadTagException decryptError) {
            throw new ProtocolError("Cannot decrypt payload");
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }

    }

    byte[] createProtectedPacketNumber(byte[] ciphertext, int packetNumber, NodeSecrets secrets) {

        //int sampleOffset = 6 + initialConnectionId.length + sourceConnectionId.length + 2 /* length(payload_length) */ + 4;
        int sampleOffset = 3;    // TODO
        byte[] sample = new byte[16];
        System.arraycopy(ciphertext, sampleOffset, sample,0,16);
        byte[] encryptedPn = encryptAesCtr(secrets.pn, sample, new byte[] { (byte) packetNumber });   // TODO: if pn > 1 byte
        return encryptedPn;
    }

    int unprotectPacketNumber(byte[] ciphertext, byte[] protectedPacketNumber, NodeSecrets secrets) {
        int sampleOffset = 4 - protectedPacketNumber.length;
        byte[] sample = new byte[16];
        System.arraycopy(ciphertext, sampleOffset, sample,0,16);
        // AES is symmetric, so decrypt is the same as encrypt
        byte[] decryptedPn = encryptAesCtr(secrets.pn, sample, protectedPacketNumber);
        return decryptedPn[0];   // TODO: assuming one byte
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

    static int parseVariableLengthInteger(ByteBuffer buffer) {
        int length;
        byte firstLengthByte = buffer.get();
        switch ((firstLengthByte & 0xc0) >> 6) {
            case 0:
                length = firstLengthByte;
                break;
            case 1:
                length = ((firstLengthByte & 0x3f) << 8) | (buffer.get() & 0xff);
                break;
            default:
                // TODO
                throw new RuntimeException("NYI");
        }
        return length;
    }

    protected void parseFrames(byte[] frameBytes, QuicConnection connection, ConnectionSecrets connectionSecrets, TlsState tlsState, Logger log) {
        ByteBuffer buffer = ByteBuffer.wrap(frameBytes);

        while (buffer.remaining() > 0) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-12.4
            // "Each frame begins with a Frame Type, indicating its type, followed by additional type-dependent fields"
            int frameType = buffer.get();
            switch (frameType) {
                case 0x00:
                    // Padding
                    break;
                case 0x02:
                    log.debug("Receiving Connection Close frame, which is not yet implemented.");
                    throw new NotYetImplementedException();
                case 0x0d:
                    if (quicVersion == Version.IETF_draft_14)
                        frames.add(new AckFrame().parse(buffer, log));
                    else
                        throw new NotYetImplementedException();
                    break;
                case 0x18:
                    CryptoFrame cryptoFrame = new CryptoFrame(connectionSecrets, tlsState).parse(buffer, log);
                    connection.getCryptoStream(getEncryptionLevel()).add(cryptoFrame);
                    frames.add(cryptoFrame);
                    break;
                case 0x1a:
                    if (quicVersion.atLeast(Version.IETF_draft_15))
                        frames.add(new AckFrame().parse(buffer, log));
                    else
                        throw new NotYetImplementedException();
                    break;
                case 0x1b:
                    if (quicVersion.atLeast(Version.IETF_draft_15))
                        frames.add(new AckFrame().parse(buffer, log));
                    else
                        throw new NotYetImplementedException();
                    break;
                default:
                    throw new NotYetImplementedException();
            }
        }
    }

    public int getPacketNumber() {
        return packetNumber;
    }

    protected abstract EncryptionLevel getEncryptionLevel();
}
