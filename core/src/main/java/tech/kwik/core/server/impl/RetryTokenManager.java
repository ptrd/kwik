/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.core.server.impl;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Creates and validates (stateless) retry tokens.
 * https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.1
 * "A token sent in a NEW_TOKEN frame or a Retry packet MUST be constructed in a way that allows the server to identify
 *  how it was provided to a client. "
 * https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4
 * "Tokens sent in Retry packets SHOULD include information that allows the server to verify that the source IP address
 *  and port in client packets remain constant."
 * "Servers SHOULD ensure that tokens sent in Retry packets are only accepted for a short time, as they are returned
 *  immediately by clients."
 *
 * The token is encrypted and authenticated with a key that is only known to this server (instance), and contains the
 * time it was issued and the original destination connection ID. The client address and the retry source connection ID
 * (which the client must use as destination connection ID when sending the token) are included as associated data,
 * so a token is only valid when it is sent from the same address and to the same connection ID.
 * Because all information needed to validate the token is contained in the token itself, no state needs to be kept
 * between sending the Retry packet and receiving the Initial packet that contains the token.
 */
public class RetryTokenManager {

    public static final Duration TOKEN_VALIDITY = Duration.ofSeconds(10);
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH = 16;
    private static final int TIMESTAMP_LENGTH = 8;

    private final int connectionIdLength;
    private final Clock clock;
    private final SecureRandom random;
    private final SecretKey key;

    public RetryTokenManager(int connectionIdLength) {
        this(connectionIdLength, Clock.systemUTC());
    }

    public RetryTokenManager(int connectionIdLength, Clock clock) {
        this.connectionIdLength = connectionIdLength;
        this.clock = clock;
        random = new SecureRandom();
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128, random);
            key = keyGenerator.generateKey();
        }
        catch (NoSuchAlgorithmException e) {
            // Impossible: AES is a mandatory algorithm for every Java platform implementation.
            throw new RuntimeException(e);
        }
    }

    /**
     * Generates the connection ID that the server uses as source connection ID in the Retry packet.
     * @return
     */
    public byte[] generateRetrySourceConnectionId() {
        byte[] connectionId = new byte[connectionIdLength];
        random.nextBytes(connectionId);
        return connectionId;
    }

    /**
     * Creates a retry token.
     * @param clientAddress  the address the client sends the initial packet from
     * @param odcid  the original destination connection ID (the destination connection ID of the initial packet that triggered the retry)
     * @param retryScid  the source connection ID of the Retry packet
     * @return
     */
    public byte[] createToken(InetSocketAddress clientAddress, byte[] odcid, byte[] retryScid) {
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);

        ByteBuffer plaintext = ByteBuffer.allocate(TIMESTAMP_LENGTH + 1 + odcid.length);
        plaintext.putLong(clock.instant().toEpochMilli());
        plaintext.put((byte) odcid.length);
        plaintext.put(odcid);

        try {
            Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, nonce, clientAddress, retryScid);
            byte[] encrypted = cipher.doFinal(plaintext.array());
            ByteBuffer token = ByteBuffer.allocate(NONCE_LENGTH + encrypted.length);
            token.put(nonce);
            token.put(encrypted);
            return token.array();
        }
        catch (GeneralSecurityException e) {
            // Impossible: AES-GCM is a mandatory algorithm for every Java platform implementation and parameters are valid.
            throw new RuntimeException(e);
        }
    }

    /**
     * Validates a retry token.
     * @param token  the token as received in the initial packet
     * @param clientAddress  the address the initial packet was received from
     * @param dcid  the destination connection ID of the initial packet
     * @return  the original destination connection ID if the token is valid, empty otherwise
     */
    public Optional<byte[]> validateToken(byte[] token, InetSocketAddress clientAddress, byte[] dcid) {
        if (token == null || token.length < NONCE_LENGTH + TIMESTAMP_LENGTH + 1 + TAG_LENGTH) {
            return Optional.empty();
        }
        try {
            Cipher cipher = initCipher(Cipher.DECRYPT_MODE, token, clientAddress, dcid);
            ByteBuffer plaintext = ByteBuffer.wrap(cipher.doFinal(token, NONCE_LENGTH, token.length - NONCE_LENGTH));

            Instant issued = Instant.ofEpochMilli(plaintext.getLong());
            Instant now = clock.instant();
            if (issued.isAfter(now) || issued.plus(TOKEN_VALIDITY).isBefore(now)) {
                return Optional.empty();
            }
            int odcidLength = plaintext.get() & 0xff;
            if (odcidLength != plaintext.remaining()) {
                return Optional.empty();
            }
            byte[] odcid = new byte[odcidLength];
            plaintext.get(odcid);
            return Optional.of(odcid);
        }
        catch (AEADBadTagException e) {
            return Optional.empty();
        }
        catch (GeneralSecurityException e) {
            // Impossible: AES-GCM is a mandatory algorithm for every Java platform implementation and parameters are valid.
            throw new RuntimeException(e);
        }
    }

    private Cipher initCipher(int mode, byte[] nonce, InetSocketAddress clientAddress, byte[] connectionId) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, key, new GCMParameterSpec(TAG_LENGTH * 8, nonce, 0, NONCE_LENGTH));
        cipher.updateAAD(associatedData(clientAddress, connectionId));
        return cipher;
    }

    private static byte[] associatedData(InetSocketAddress clientAddress, byte[] connectionId) {
        byte[] address = clientAddress.getAddress().getAddress();
        ByteBuffer buffer = ByteBuffer.allocate(1 + address.length + 2 + 1 + connectionId.length);
        buffer.put((byte) address.length);
        buffer.put(address);
        buffer.putShort((short) clientAddress.getPort());
        buffer.put((byte) connectionId.length);
        buffer.put(connectionId);
        return buffer.array();
    }
}
