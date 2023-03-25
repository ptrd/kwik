/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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

/**
 * https://www.rfc-editor.org/rfc/rfc9001.html#name-packet-protection
 * "As with TLS over TCP, QUIC protects packets with keys derived from the TLS handshake, using the AEAD algorithm [AEAD]
 *  negotiated by TLS."
 */
public interface Aead {

    void computeKeys(byte[] trafficSecret);

    byte[] createHeaderProtectionMask(byte[] sample);

    byte[] getWriteIV();

    byte[] aeadEncrypt(byte[] associatedData, byte[] message, byte[] nonce);

    byte[] aeadDecrypt(byte[] associatedData, byte[] message, byte[] nonce) throws DecryptionException;

    /**
     * Check whether the key phase carried by a received packet still matches the current key phase; if not, compute
     * new keys (to be used for decryption). Note that the changed key phase can also be caused by packet corruption,
     * so it is not yet sure whether a key update is really in progress (this will be sure when decryption of the packet
     * failed or succeeded).
     * @param keyPhaseBit
     */
    void checkKeyPhase(short keyPhaseBit);

    /**
     * Compute new keys. Note that depending on the role of this Keys object, computing new keys concerns updating
     * the write secrets (role that initiates the key update) or the read secrets (role that responds to the key update).
     * @param selfInitiated        true when this role initiated the key update, so updating write secrets.
     */
    void computeKeyUpdate(boolean selfInitiated);

    /**
     * Confirm that, if a key update was in progress, it has been successful and thus the new keys can (and should) be
     * used for decrypting all incoming packets.
     */
    void confirmKeyUpdateIfInProgress();

    /**
     * Confirm that, if a key update was in progress, it has been unsuccessful and thus the new keys should not be
     * used for decrypting all incoming packets.
     */
    void cancelKeyUpdateIfInProgress();

    short getKeyPhase();

    int getKeyUpdateCounter();

    void setPeerAead(Aead peerAead);

    byte[] getTrafficSecret();
}
