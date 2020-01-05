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
package net.luminis.quic.packet;

import net.luminis.quic.*;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.Logger;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

abstract public class QuicPacket {

    protected static final int MAX_PACKET_SIZE = 1500;

    protected Version quicVersion;
    protected long packetNumber = -1;
    protected List<QuicFrame> frames = new ArrayList<>();
    protected int packetSize = -1;

    public QuicPacket() {
        frames = new ArrayList<>();
    }

    static byte[] encodePacketNumber(long packetNumber) {
        if (packetNumber <= 0xff) {
            return new byte[] { (byte) packetNumber };
        }
        else if (packetNumber <= 0xffff) {
            return new byte[] { (byte) (packetNumber >> 8), (byte) (packetNumber & 0x00ff) };
        }
        else if (packetNumber <= 0xffffff) {
            return new byte[] { (byte) (packetNumber >> 16), (byte) (packetNumber >> 8), (byte) (packetNumber & 0x00ff) };
        }
        else if (packetNumber <= 0xffffffffL) {
            return new byte[] { (byte) (packetNumber >> 24), (byte) (packetNumber >> 16), (byte) (packetNumber >> 8), (byte) (packetNumber & 0x00ff) };
        }
        else {
            throw new NotYetImplementedException("cannot encode pn > 4 bytes");
        }
    }

    /**
     * Updates the given flags byte to encode the packet number length that is used for encoding the given packet number.
     * @param flags
     * @param packetNumber
     * @return
     */
    static byte encodePacketNumberLength(byte flags, long packetNumber) {
        if (packetNumber <= 0xff) {
            return flags;
        }
        else if (packetNumber <= 0xffff) {
            return (byte) (flags | 0x01);
        }
        else if (packetNumber <= 0xffffff) {
            return (byte) (flags | 0x02);
        }
        else if (packetNumber <= 0xffffffffL) {
            return (byte) (flags | 0x03);
        }
        else {
            throw new NotYetImplementedException("cannot encode pn > 4 bytes");
        }
    }

    void parsePacketNumberAndPayload(ByteBuffer buffer, byte flags, int remainingLength, Keys serverSecrets, long largestPacketNumber, Logger log) throws DecryptionException {

        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.3
        // "When removing packet protection, an endpoint
        //   first removes the header protection."

        int currentPosition = buffer.position();
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.2:
        // "The same number of bytes are always sampled, but an allowance needs
        //   to be made for the endpoint removing protection, which will not know
        //   the length of the Packet Number field.  In sampling the packet
        //   ciphertext, the Packet Number field is assumed to be 4 bytes long
        //   (its maximum possible encoded length)."
        buffer.position(currentPosition + 4);
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.2:
        // "This algorithm samples 16 bytes from the packet ciphertext."
        byte[] sample = new byte[16];
        buffer.get(sample);
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
        // "Header protection is applied after packet protection is applied (see
        //   Section 5.3).  The ciphertext of the packet is sampled and used as
        //   input to an encryption algorithm."
        byte[] mask = createHeaderProtectionMask(sample, serverSecrets);
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1
        // "The output of this algorithm is a 5 byte mask which is applied to the
        //   protected header fields using exclusive OR.  The least significant
        //   bits of the first byte of the packet are masked by the least
        //   significant bits of the first mask byte"
        byte decryptedFlags;
        if ((flags & 0x80) == 0x80) {
            // Long header: 4 bits masked
            decryptedFlags = (byte) (flags ^ mask[0] & 0x0f);
        }
        else {
            // Short header: 5 bits masked
            decryptedFlags = (byte) (flags ^ mask[0] & 0x1f);
        }
        setUnprotectedHeader(decryptedFlags);
        buffer.position(currentPosition);

        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
        // "pn_length = (packet[0] & 0x03) + 1"
        int protectedPackageNumberLength = (decryptedFlags & 0x03) + 1;
        byte[] protectedPackageNumber = new byte[protectedPackageNumberLength];
        buffer.get(protectedPackageNumber);

        byte[] unprotectedPacketNumber = new byte[protectedPackageNumberLength];
        for (int i = 0; i < protectedPackageNumberLength; i++) {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
            // " ...and the packet number is
            //   masked with the remaining bytes.  Any unused bytes of mask that might
            //   result from a shorter packet number encoding are unused."
            unprotectedPacketNumber[i] = (byte) (protectedPackageNumber[i] ^ mask[1+i]);
        }
        packetNumber = bytesToInt(unprotectedPacketNumber);
        packetNumber = decodePacketNumber(packetNumber, largestPacketNumber, protectedPackageNumberLength * 8);
        log.decrypted("Unprotected packet number: " + packetNumber);

        currentPosition = buffer.position();
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.3
        // "The associated data, A, for the AEAD is the contents of the QUIC
        //   header, starting from the flags byte in either the short or long
        //   header, up to and including the unprotected packet number."
        byte[] frameHeader = new byte[buffer.position()];
        buffer.position(0);
        buffer.get(frameHeader);
        frameHeader[0] = decryptedFlags;
        buffer.position(currentPosition);

        // Copy unprotected (decrypted) packet number in frame header, before decrypting payload.
        System.arraycopy(unprotectedPacketNumber, 0, frameHeader, frameHeader.length - (protectedPackageNumberLength), protectedPackageNumberLength);
        log.encrypted("Frame header", frameHeader);

        // "The input plaintext, P, for the AEAD is the payload of the QUIC
        //   packet, as described in [QUIC-TRANSPORT]."
        // "The output ciphertext, C, of the AEAD is transmitted in place of P."
        int encryptedPayloadLength = remainingLength - protectedPackageNumberLength;
        byte[] payload = new byte[encryptedPayloadLength];
        buffer.get(payload, 0, encryptedPayloadLength);
        log.encrypted("Encrypted payload", payload);

        byte[] frameBytes = decryptPayload(payload, frameHeader, packetNumber, serverSecrets);
        log.decrypted("Decrypted payload", frameBytes);

        frames = new ArrayList<>();
        parseFrames(frameBytes, log);
    }

    protected void setUnprotectedHeader(byte decryptedFlags) {}

    byte[] createHeaderProtectionMask(byte[] sample, Keys secrets) {
        return createHeaderProtectionMask(sample, 4, secrets);
    }

    byte[] createHeaderProtectionMask(byte[] ciphertext, int encodedPacketNumberLength, Keys secrets) {
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4
        // "The same number of bytes are always sampled, but an allowance needs
        //   to be made for the endpoint removing protection, which will not know
        //   the length of the Packet Number field.  In sampling the packet
        //   ciphertext, the Packet Number field is assumed to be 4 bytes long
        //   (its maximum possible encoded length)."
        int sampleOffset = 4 - encodedPacketNumberLength;
        byte[] sample = new byte[16];
        System.arraycopy(ciphertext, sampleOffset, sample, 0, 16);
        byte[] mask = encryptAesEcb(secrets.getHp(), sample);
        return mask;
    }


    byte[] encryptPayload(byte[] message, byte[] associatedData, long packetNumber, Keys secrets) {

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
        // "The nonce, N, is formed by combining the packet
        //   protection IV with the packet number.  The 64 bits of the
        //   reconstructed QUIC packet number in network byte order are left-
        //   padded with zeros to the size of the IV.  The exclusive OR of the
        //   padded packet number and the IV forms the AEAD nonce"
        byte[] writeIV = secrets.getWriteIV();
        ByteBuffer nonceInput = ByteBuffer.allocate(writeIV.length);
        for (int i = 0; i < nonceInput.capacity() - 8; i++)
            nonceInput.put((byte) 0x00);
        nonceInput.putLong(packetNumber);

        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ writeIV[i++]);

        try {
            SecretKeySpec secretKey = new SecretKeySpec(secrets.getWriteKey(), "AES");
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

    byte[] decryptPayload(byte[] message, byte[] associatedData, long packetNumber, Keys secrets) throws DecryptionException {
        ByteBuffer nonceInput = ByteBuffer.allocate(12);
        nonceInput.putInt(0);
        nonceInput.putLong(packetNumber);

        byte[] writeIV = secrets.getWriteIV();
        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ writeIV[i++]);

        try {
            SecretKeySpec secretKey = new SecretKeySpec(secrets.getWriteKey(), "AES");
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
            throw new DecryptionException();
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }

    }

    static long decodePacketNumber(long truncatedPacketNumber, long largestPacketNumber, int bits) {
        long expectedPacketNumber = largestPacketNumber + 1;
        long pnWindow = 1L << bits;
        long pnHalfWindow = pnWindow / 2;
        long pnMask = ~ (pnWindow - 1);

        long candidatePn = (expectedPacketNumber & pnMask) | truncatedPacketNumber;
        if (candidatePn <= expectedPacketNumber - pnHalfWindow) {
            return candidatePn + pnWindow;
        }
        if (candidatePn > expectedPacketNumber + pnHalfWindow && candidatePn > pnWindow) {
            return candidatePn - pnWindow;
        }

        return candidatePn;
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

    byte[] encryptAesEcb(byte[] key, byte[] value) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            byte[] encrypted = cipher.doFinal(value);
            return encrypted;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Inappropriate runtime environment
            throw new QuicRuntimeException(e);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
    }

    protected void parseFrames(byte[] frameBytes, Logger log) {
        ByteBuffer buffer = ByteBuffer.wrap(frameBytes);

        while (buffer.remaining() > 0) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-12.4
            // "Each frame begins with a Frame Type, indicating its type, followed by additional type-dependent fields"
            buffer.mark();
            int frameType = buffer.get();
            buffer.reset();
            switch (frameType) {
                case 0x00:
                    frames.add(new Padding().parse(buffer, log));
                    break;
                case 0x01:
                    frames.add(new PingFrame(quicVersion).parse(buffer, log));
                    break;
                case 0x02:
                case 0x03:
                    frames.add(new AckFrame().parse(buffer, log));
                    break;
                case 0x04:
                    frames.add(new ResetStreamFrame().parse(buffer, log));
                    break;
                case 0x05:
                    frames.add(new StopSendingFrame(quicVersion).parse(buffer, log));
                    break;
                case 0x06:
                    frames.add(new CryptoFrame().parse(buffer, log));
                    break;
                case 0x07:
                    frames.add(new NewTokenFrame().parse(buffer, log));
                    break;
                case 0x10:
                    frames.add(new MaxDataFrame().parse(buffer, log));
                    break;
                case 0x011:
                    frames.add(new MaxStreamDataFrame().parse(buffer, log));
                    break;
                case 0x12:
                case 0x13:
                    frames.add(new MaxStreamsFrame().parse(buffer, log));
                    break;
                case 0x14:
                    frames.add(new DataBlockedFrame().parse(buffer, log));
                    break;
                case 0x15:
                    frames.add(new StreamDataBlockedFrame().parse(buffer, log));
                    break;
                case 0x16:
                case 0x17:
                    frames.add(new StreamsBlockedFrame().parse(buffer, log));
                    break;
                case 0x18:
                    frames.add(new NewConnectionIdFrame(quicVersion).parse(buffer, log));
                    break;
                case 0x19:
                    frames.add(new RetireConnectionIdFrame(quicVersion).parse(buffer, log));
                    break;
                case 0x1a:
                    frames.add(new PathChallengeFrame(quicVersion).parse(buffer, log));
                    break;
                case 0x1b:
                    frames.add(new PathResponseFrame(quicVersion).parse(buffer, log));
                    break;
                case 0x1c:
                case 0x1d:
                    frames.add(new ConnectionCloseFrame(quicVersion).parse(buffer, log));
                    break;
                default:
                    if ((frameType >= 0x08) && (frameType <= 0x0f)) {
                        frames.add(new StreamFrame().parse(buffer, log));
                    }
                    else {
                        // https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-12.4
                        // "An endpoint MUST treat the receipt of a frame of unknown type as a connection error of type FRAME_ENCODING_ERROR."
                        throw new ProtocolError("connection error FRAME_ENCODING_ERROR");
                    }
            }
        }
    }

    public Long getPacketNumber() {
        if (packetNumber >= 0) {
            return packetNumber;
        }
        else {
            throw new IllegalStateException("PN is not yet known");
        }
    }

    protected void protectPacketNumberAndPayload(ByteBuffer packetBuffer, int packetNumberSize, ByteBuffer payload, int paddingSize, Keys clientSecrets) {
        int packetNumberPosition = packetBuffer.position() - packetNumberSize;

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
        // "The associated data, A, for the AEAD is the contents of the QUIC
        //   header, starting from the flags octet in either the short or long
        //   header, up to and including the unprotected packet number."
        int additionalDataSize = packetBuffer.position();
        byte[] additionalData = new byte[additionalDataSize];
        packetBuffer.flip();  // Prepare for reading from start
        packetBuffer.get(additionalData);  // Position is now where it was at start of this method.
        packetBuffer.limit(packetBuffer.capacity());  // Ensure we can continue writing

        byte[] paddedPayload = new byte[payload.limit() + paddingSize];
        payload.get(paddedPayload, 0, payload.limit());
        byte[] encryptedPayload = encryptPayload(paddedPayload, additionalData, packetNumber, clientSecrets);
        packetBuffer.put(encryptedPayload);

        byte[] protectedPacketNumber;
        byte[] encodedPacketNumber = encodePacketNumber(packetNumber);
        byte[] mask = createHeaderProtectionMask(encryptedPayload, encodedPacketNumber.length, clientSecrets);

        protectedPacketNumber = new byte[encodedPacketNumber.length];
        for (int i = 0; i < encodedPacketNumber.length; i++) {
            protectedPacketNumber[i] = (byte) (encodedPacketNumber[i] ^ mask[1+i]);
        }

        byte flags = packetBuffer.get(0);
        if ((flags & 0x80) == 0x80) {
            // Long header: 4 bits masked
            flags ^= mask[0] & 0x0f;
        }
        else {
            // Short header: 5 bits masked
            flags ^= mask[0] & 0x1f;
        }
        packetBuffer.put(0, flags);

        int currentPosition = packetBuffer.position();
        packetBuffer.position(packetNumberPosition);
        packetBuffer.put(protectedPacketNumber);
        packetBuffer.position(currentPosition);
    }

    static int bytesToInt(byte[] data) {
        int value = 0;
        for (int i = 0; i < data.length; i++) {
            value = (value << 8) | (data[i] & 0xff);

        }
        return value;
    }

    public void addFrame(QuicFrame frame) {
        frames.add(frame);
    }

    public int getSize() {
        if (packetSize > 0) {
            return packetSize;
        }
        else {
            throw new IllegalStateException("no size");
        }
    }

    public abstract EncryptionLevel getEncryptionLevel();

    public abstract PnSpace getPnSpace();

    public abstract byte[] generatePacketBytes(long packetNumber, Keys keys);

    public abstract void parse(ByteBuffer data, Keys keys, long largestPacketNumber, Logger log, int sourceConnectionIdLength) throws DecryptionException;

    public List<QuicFrame> getFrames() {
        return frames;
    }

    public PacketId getId() {
        return new PacketId(getPnSpace(), getPacketNumber());
    }

    public abstract void accept(PacketProcessor processor, Instant time);

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-recovery-18#section-2
     * "Crypto Packets:  Packets containing CRYPTO data sent in Initial or Handshake packets."
     * @return whether packet is a Crypto Packet
     */
    public boolean isCrypto() {
        return !getEncryptionLevel().equals(EncryptionLevel.App)
            && frames.stream().filter(f -> f instanceof CryptoFrame).findFirst().isPresent();
    }

    public QuicPacket copy() {
        throw new IllegalStateException();
    }

    public boolean canBeAcked() {
        return true;
    }

    public boolean isAckEliciting() {
        return frames.stream().anyMatch(frame -> frame.isAckEliciting());
    }

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-20#section-2
    // "ACK-only:  Any packet containing only one or more ACK frame(s)."
    public boolean isAckOnly() {
        return frames.stream().allMatch(frame -> frame instanceof AckFrame);
    }
}
