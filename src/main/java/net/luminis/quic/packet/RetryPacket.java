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
import net.luminis.quic.log.Logger;
import net.luminis.tls.ByteUtils;

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
    // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8:
    // "The secret key, K, is 128 bits equal to 0x4d32ecdb2a2133c841e4043df27d4430."
    public static final byte[] SECRET_KEY = new byte[] { 0x4d, 0x32, (byte) 0xec, (byte) 0xdb, 0x2a, 0x21, 0x33, (byte) 0xc8,
            0x41, (byte) 0xe4, 0x04, 0x3d, (byte) 0xf2, 0x7d, 0x44, 0x30 };
    // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8:
    // "The nonce, N, is 96 bits equal to 0x4d1611d05513a552c587d575."
    public static final byte[] NONCE = new byte[] { 0x4d, 0x16, 0x11, (byte) 0xd0, 0x55, 0x13, (byte) 0xa5, 0x52,
            (byte) 0xc5, (byte) 0x87, (byte) 0xd5, 0x75 };

    private int packetSize;
    private byte[] sourceConnectionId;
    private byte[] destinationConnectionId;
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
    public void parse(ByteBuffer buffer, Keys keys, long largestPacketNumber, Logger log, int sourceConnectionIdLength) throws DecryptionException {
        log.debug("Parsing " + this.getClass().getSimpleName());
        packetSize = buffer.limit() - buffer.position();
        rawPacketData = new byte[packetSize];
        buffer.mark();
        buffer.get(rawPacketData);
        buffer.reset();

        byte flags = buffer.get();

        try {
            Version quicVersion = Version.parse(buffer.getInt());
        } catch (UnknownVersionException e) {
            // Protocol error: if it gets here, server should match the Quic version we sent
            throw new ProtocolError("Server uses unsupported Quic version");
        }

        int dstConnIdLength = buffer.get();
        destinationConnectionId = new byte[dstConnIdLength];
        buffer.get(destinationConnectionId);

        int srcConnIdLength = buffer.get();
        sourceConnectionId = new byte[srcConnIdLength];
        buffer.get(sourceConnectionId);

        log.debug("Destination connection id", destinationConnectionId);
        log.debug("Source connection id", sourceConnectionId);

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
        ByteBuffer pseudoPacket = ByteBuffer.allocate(1 + originalDestinationConnectionId.length + 1 + 4 +
                1 + destinationConnectionId.length + 1 + sourceConnectionId.length + retryToken.length);
        pseudoPacket.put((byte) originalDestinationConnectionId.length);
        pseudoPacket.put(originalDestinationConnectionId);
        pseudoPacket.put(rawPacketData, 0, rawPacketData.length - RETRY_INTEGRITY_TAG_LENGTH);

        try {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8
            // "The Retry Integrity Tag is a 128-bit field that is computed as the output of AEAD_AES_128_GCM [AEAD]..."
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY, "AES");
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, NONCE);
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            aeadCipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8
            // "The associated data, A, is the contents of the Retry Pseudo-Packet"
            aeadCipher.updateAAD(pseudoPacket.array());
            // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8
            // "The plaintext, P, is empty."
            byte[] cipherText = aeadCipher.doFinal(new byte[0]);
            return Arrays.equals(cipherText, retryIntegrityTag);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Inappropriate runtime environment
            throw new QuicRuntimeException(e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }

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
    public void accept(PacketProcessor processor, Instant time) {
        processor.process(this, time);
    }

    @Override
    public byte[] generatePacketBytes(long packetNumber, Keys keys) {
        return new byte[0];
    }

    @Override
    public boolean canBeAcked() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-17.2.5
        // "A Retry packet does not include a packet number and cannot be explicitly acknowledged by a client."
        return false;
    }

    public byte[] getRetryToken() {
        return retryToken;
    }

    public byte[] getDestinationConnectionId() {
        return destinationConnectionId;
    }

    public byte[] getSourceConnectionId() {
        return sourceConnectionId;
    }

    public byte[] getOriginalDestinationConnectionId() {
        return originalDestinationConnectionId;
    }

    /**/
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
