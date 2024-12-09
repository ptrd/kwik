/*
 * Copyright © 2024 Peter Doornbosch
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

import net.luminis.quic.impl.DecryptionException;
import net.luminis.quic.impl.Role;
import net.luminis.quic.log.Logger;
import net.luminis.quic.util.TriFunction;

/**
 * This class is a wrapper around an Aead object that supports key updates.
 * When a key update is triggered by this endpoint, the new keys are computed and installed immediately.
 * When a key update is triggered by the peer, the decryption of packets is done with the updated keys, but the keys
 * are not installed permanently until the decryption of the packet that introduced the new key phase has succeeded.
 */
public class KeyUpdateSupport implements Aead {

    private final Role role;
    private final TriFunction<Role, byte[], byte[], Aead> aeadFactory;
    private final Logger log;
    private volatile Aead aead;
    private volatile Aead updatedAead;
    private volatile int keyUpdateCounter;
    private volatile boolean possibleKeyUpdateInProgresss;
    private volatile Aead peerAead;

    public KeyUpdateSupport(Aead aead, Role role, TriFunction<Role, byte[], byte[], Aead> aeadFactory, Logger log) {
        this.aead = aead;
        this.role = role;
        this.aeadFactory = aeadFactory;
        this.log = log;
    }

    @Override
    public byte[] createHeaderProtectionMask(byte[] sample) {
        return aead.createHeaderProtectionMask(sample);
    }

    @Override
    public byte[] getIv() {
        if (possibleKeyUpdateInProgresss) {
            return updatedAead.getIv();
        }
        else {
            return aead.getIv();
        }
    }

    @Override
    public byte[] aeadEncrypt(byte[] associatedData, byte[] message, byte[] nonce) {
        return aead.aeadEncrypt(associatedData, message, nonce);
    }

    @Override
    public byte[] aeadDecrypt(byte[] associatedData, byte[] message, byte[] nonce) throws DecryptionException {
        if (possibleKeyUpdateInProgresss) {
            return updatedAead.aeadDecrypt(associatedData, message, nonce);
        }
        else {
            return aead.aeadDecrypt(associatedData, message, nonce);
        }
    }

    /**
     * Check whether the key phase carried by a received packet still matches the current key phase; if not, compute
     * new keys (to be used for decryption). Note that the changed key phase can also be caused by packet corruption,
     * so it is not yet sure whether a key update is really in progress (this will be sure when decryption of the packet
     * failed or succeeded).
     * @param keyPhaseBit
     */
    @Override
    public void checkKeyPhase(short keyPhaseBit) {
        if ((keyUpdateCounter % 2) != keyPhaseBit) {
            if (updatedAead == null) {
                createNewAead();
                log.secret("Computed new (updated) iv", updatedAead.getIv());
            }
            log.info("Received key phase does not match current => possible key update in progress");
            possibleKeyUpdateInProgresss = true;
        }
    }

    private void createNewAead() {
        byte[] newApplicationTrafficSecret = aead.computeNextApplicationTrafficSecret();
        boolean selfInitiated = false;
        log.secret("Updated ApplicationTrafficSecret (" + (selfInitiated? "self":"peer") + "): ", newApplicationTrafficSecret);
        updatedAead = aeadFactory.apply(role, newApplicationTrafficSecret, aead.getHp());
    }

    /**
     * Compute new keys. Note that depending on the role of this Keys object, computing new keys concerns updating
     * the write secrets (role that initiates the key update) or the read secrets (role that responds to the key update).
     * @param selfInitiated        true when this role initiated the key update, so updating write secrets.
     */
    @Override
    public void computeKeyUpdate(boolean selfInitiated) {
        createNewAead();
        if (selfInitiated) {
            // If updating was self initiated, the new keys can be installed immediately.
            keyUpdateCounter++;
            aead = updatedAead;
        }
        // Else, updating was initiated by receiving a packet with different key phase, and the new keys can only be
        // installed permanently if the decryption of the packet (that introduced the new key phase) has succeeded,
        // which is done by confirmKeyUpdateIfInProgress().
    }

    @Override
    public byte[] computeNextApplicationTrafficSecret() {
        return aead.computeNextApplicationTrafficSecret();
    }

    @Override
    public void confirmKeyUpdateIfInProgress() {
        if (possibleKeyUpdateInProgresss) {
            log.info("Installing updated keys (initiated by peer)");
            keyUpdateCounter++;
            aead = updatedAead;
            updatedAead = null;
            possibleKeyUpdateInProgresss = false;
            checkPeerKeys();
        }
    }

    private void checkPeerKeys() {
        if (peerAead.getKeyUpdateCounter() < keyUpdateCounter) {
            log.info("Keys out of sync; updating keys for peer");
            peerAead.computeKeyUpdate(true);
        }
    }

    @Override
    public void cancelKeyUpdateIfInProgress() {
        if (possibleKeyUpdateInProgresss) {
            log.info("Discarding updated keys (initiated by peer)");
            possibleKeyUpdateInProgresss = false;
            updatedAead = null;
        }
    }

    @Override
    public short getKeyPhase() {
        return (short) (keyUpdateCounter % 2);
    }

    @Override
    public int getKeyUpdateCounter() {
        return keyUpdateCounter;
    }

    @Override
    public void setPeerAead(Aead peerAead) {
        this.peerAead = peerAead;
    }

    @Override
    public byte[] getTrafficSecret() {
        return aead.getTrafficSecret();
    }

    @Override
    public byte[] getHp() {
        return new byte[0];
    }
}
