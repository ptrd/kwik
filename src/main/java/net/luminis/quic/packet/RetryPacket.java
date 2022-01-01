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
package net.luminis.quic.packet;

import net.luminis.quic.*;
import net.luminis.quic.crypto.Keys;
import net.luminis.quic.log.Logger;
import net.luminis.tls.util.ByteUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;

/**
 * See https://tools.ietf.org/html/draft-ietf-quic-transport-25#section-17.2.5
 */
public class RetryPacket extends QuicPacket {

    public static final int RETRY_INTEGRITY_TAG_LENGTH = 16;    // The Retry Integrity Tag is 128 bits.
    // https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.8
    // "The secret key, K, is 128 bits equal to 0xccce187ed09a09d05728155a6cb96be1."
    public static final byte[] SECRET_KEY = new byte[] {
            (byte) 0xcc, (byte) 0xce, (byte) 0x18, (byte) 0x7e, (byte) 0xd0, (byte) 0x9a, (byte) 0x09, (byte) 0xd0,
            (byte) 0x57, (byte) 0x28, (byte) 0x15, (byte) 0x5a, (byte) 0x6c, (byte) 0xb9, (byte) 0x6b, (byte) 0xe1 };

    public static final byte[] SECRET_KEY_V1 = new byte[] {
            (byte) 0xbe, (byte) 0x0c, (byte) 0x69, (byte) 0x0b, (byte) 0x9f, (byte) 0x66, (byte) 0x57, (byte) 0x5a,
            (byte) 0x1d, (byte) 0x76, (byte) 0x6b, (byte) 0x54, (byte) 0xe3, (byte) 0x68, (byte) 0xc8, (byte) 0x4e };

    // https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.8
    // "The nonce, N, is 96 bits equal to 0xe54930f97f2136f0530a8c1c."
    public static final byte[] NONCE = new byte[] {
            (byte) 0xe5, (byte) 0x49, (byte) 0x30, (byte) 0xf9, (byte) 0x7f, (byte) 0x21, (byte) 0x36, (byte) 0xf0,
            (byte) 0x53, (byte) 0x0a, (byte) 0x8c, (byte) 0x1c };

    public static final byte[] NONCE_V1 = new byte[] {
            (byte) 0x46, (byte) 0x15, (byte) 0x99, (byte) 0xd3, (byte) 0x5d, (byte) 0x63, (byte) 0x2b, (byte) 0xf2,
            (byte) 0x23, (byte) 0x98, (byte) 0x25, (byte) 0xbb };

    // Minimal length for a valid packet:  type version dcid len dcid scid len scid retry-integrety-tag
    private static int MIN_PACKET_LENGTH = 1 +  4 +     1 +      0 +  1 +      0 +  16;


    private byte[] sourceConnectionId;

    private byte[] originalDestinationConnectionId;
    private byte[] retryToken;
    private byte[] rawPacketData;
    private byte[] retryIntegrityTag;


    public RetryPacket(Version quicVersion) {
        this.quicVersion = quicVersion;
    }

    public RetryPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destinationConnectionId, byte[] originalDestinationConnectionId, byte[] retryToken) {
        this.quicVersion = quicVersion;
        this.sourceConnectionId = sourceConnectionId;
        this.destinationConnectionId = destinationConnectionId;
        this.originalDestinationConnectionId = originalDestinationConnectionId;
        this.retryToken = retryToken;
        this.rawPacketData = new byte[1 + 4 + 1 + destinationConnectionId.length + 1 + sourceConnectionId.length +
                retryToken.length + RETRY_INTEGRITY_TAG_LENGTH];
    }

    @Override
    public void parse(ByteBuffer buffer, Keys keys, long largestPacketNumber, Logger log, int sourceConnectionIdLength) throws DecryptionException, InvalidPacketException {
        log.debug("Parsing " + this.getClass().getSimpleName());
        if (buffer.remaining() < MIN_PACKET_LENGTH) {
            throw new InvalidPacketException();
        }

        packetSize = buffer.remaining();
        rawPacketData = new byte[packetSize];
        buffer.mark();
        buffer.get(rawPacketData);
        buffer.reset();

        byte flags = buffer.get();

        boolean matchingVersion = false;
        try {
            matchingVersion = Version.parse(buffer.getInt()) == this.quicVersion;
        } catch (UnknownVersionException e) {}

        if (! matchingVersion) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-5.2
            // "... packets are discarded if they indicate a different protocol version than that of the connection..."
            throw new InvalidPacketException();
        }

        int dstConnIdLength = buffer.get();
        if (buffer.remaining() < dstConnIdLength + 1 + RETRY_INTEGRITY_TAG_LENGTH) {
            throw new InvalidPacketException();
        }
        destinationConnectionId = new byte[dstConnIdLength];
        buffer.get(destinationConnectionId);

        int srcConnIdLength = buffer.get();
        if (buffer.remaining() < srcConnIdLength) {
            throw new InvalidPacketException();
        }
        sourceConnectionId = new byte[srcConnIdLength];
        buffer.get(sourceConnectionId);

        log.debug("Destination connection id", destinationConnectionId);
        log.debug("Source connection id", sourceConnectionId);

        if (buffer.remaining() < RETRY_INTEGRITY_TAG_LENGTH) {
            throw new InvalidPacketException();
        }
        int retryTokenLength = buffer.remaining() - RETRY_INTEGRITY_TAG_LENGTH;
        retryToken = new byte[retryTokenLength];
        buffer.get(retryToken);

        retryIntegrityTag = new byte[RETRY_INTEGRITY_TAG_LENGTH];
        buffer.get(retryIntegrityTag);
    }

    /**
     * Validates the Retry Integrity Tag that is carried by this packet.
     * @param originalDestinationConnectionId
     * @return
     */
    public boolean validateIntegrityTag(byte[] originalDestinationConnectionId) {
        return Arrays.equals(computeIntegrityTag(originalDestinationConnectionId), retryIntegrityTag);
    }

    @Override
    public EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.Initial;
    }

    @Override
    public PnSpace getPnSpace() {
        return null;
    }

    @Override
    public Long getPacketNumber() {
        // Retry Packet doesn't have a packet number
        return null;
    }

    @Override
    public int estimateLength(int additionalPayload) {
        throw new NotYetImplementedException();
    }

    @Override
    public PacketProcessor.ProcessResult accept(PacketProcessor processor, Instant time) {
        return processor.process(this, time);
    }

    @Override
    public byte[] generatePacketBytes(Long packetNumber, Keys keys) {
        packetSize = 1 + 4 + 1 + destinationConnectionId.length + 1 + sourceConnectionId.length + retryToken.length + 16;
        ByteBuffer buffer = ByteBuffer.allocate(packetSize);
        buffer.put((byte) 0b11110000);
        buffer.put(quicVersion.getBytes());
        buffer.put((byte) destinationConnectionId.length);
        buffer.put(destinationConnectionId);
        buffer.put((byte) sourceConnectionId.length);
        buffer.put(sourceConnectionId);
        buffer.put(retryToken);
        rawPacketData = buffer.array();
        buffer.put(computeIntegrityTag(originalDestinationConnectionId));
        return buffer.array();
    }

    private byte[] computeIntegrityTag(byte[] originalDestinationConnectionId) {
        ByteBuffer pseudoPacket = ByteBuffer.allocate(1 + originalDestinationConnectionId.length + 1 + 4 +
                1 + destinationConnectionId.length + 1 + sourceConnectionId.length + retryToken.length);
        pseudoPacket.put((byte) originalDestinationConnectionId.length);
        pseudoPacket.put(originalDestinationConnectionId);
        pseudoPacket.put(rawPacketData, 0, rawPacketData.length - RETRY_INTEGRITY_TAG_LENGTH);

        try {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8
            // "The Retry Integrity Tag is a 128-bit field that is computed as the output of AEAD_AES_128_GCM [AEAD]..."
            SecretKeySpec secretKey = new SecretKeySpec(quicVersion == Version.QUIC_version_1? SECRET_KEY_V1: SECRET_KEY, "AES");
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, quicVersion == Version.QUIC_version_1? NONCE_V1: NONCE);
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            aeadCipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8
            // "The associated data, A, is the contents of the Retry Pseudo-Packet"
            aeadCipher.updateAAD(pseudoPacket.array());
            // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8
            // "The plaintext, P, is empty."
            byte[] cipherText = aeadCipher.doFinal(new byte[0]);
            return cipherText;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Inappropriate runtime environment
            throw new QuicRuntimeException(e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
    }

    @Override
    public boolean canBeAcked() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-17.2.5
        // "A Retry packet does not include a packet number and cannot be explicitly acknowledged by a client."
        return false;
    }

    @Override
    public boolean isInflightPacket() {
        return false;
    }

    @Override
    public boolean isAckEliciting() {
        return false;
    }

    @Override
    public boolean isAckOnly() {
        return false;
    }

    public byte[] getRetryToken() {
        return retryToken;
    }

    public byte[] getSourceConnectionId() {
        return sourceConnectionId;
    }

    @Override
    public String toString() {
        return "Packet "
                + getEncryptionLevel().name().charAt(0) + "|"
                + "-" + "|"
                + "R" + "|"
                + packetSize + "|"
                + " Retry Token (" + retryToken.length + "): " + ByteUtils.bytesToHex(retryToken);
    }
}
