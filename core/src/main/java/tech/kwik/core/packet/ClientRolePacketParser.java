/*
 * Copyright © 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.packet;

import tech.kwik.core.impl.InvalidPacketException;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.crypto.MissingKeysException;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.NullLogger;

import java.nio.ByteBuffer;
import java.util.function.BiFunction;

import static tech.kwik.core.common.EncryptionLevel.App;
import static tech.kwik.core.common.EncryptionLevel.Handshake;
import static tech.kwik.core.common.EncryptionLevel.Initial;

/**
 * Packet parser for endpoint that has client role.
 */
public class ClientRolePacketParser extends PacketParser {

    private volatile byte[] originalDestinationConnectionId;

    public ClientRolePacketParser(ConnectionSecrets secrets, VersionHolder quicVersion, int cidLength, byte[] originalDestinationConnectionId, PacketFilter processor, BiFunction<ByteBuffer, Exception, Boolean> handleUnprotectPacketFailureFunction, Logger logger) {
        super(secrets, quicVersion, cidLength, processor, handleUnprotectPacketFailureFunction, Role.Client, logger);
        this.originalDestinationConnectionId = originalDestinationConnectionId;
    }

    protected Aead getAead(QuicPacket packet, ByteBuffer data) throws MissingKeysException, InvalidPacketException {
        Aead aead;
        if (packet.getVersion().equals(quicVersion.getVersion())) {
            aead = connectionSecrets.getPeerAead(packet.getEncryptionLevel());
        }
        else if (packet.getEncryptionLevel() == App || packet.getEncryptionLevel() == Handshake) {
            // https://www.rfc-editor.org/rfc/rfc9369.html#name-compatible-negotiation-requ
            // "Both endpoints MUST send Handshake or 1-RTT packets using the negotiated version. An endpoint MUST
            //  drop packets using any other version."
            log.warn("Dropping packet not using negotiated version");
            throw new InvalidPacketException("invalid version");
        }
        else if (packet.getEncryptionLevel() == Initial) {
            log.info(String.format("Receiving packet with version %s, while connection version is %s", packet.getVersion(), quicVersion));
            // Need other secrets to decrypt packet; when version negotiation succeeds, connection version will be adapted.
            ConnectionSecrets altSecrets = new ConnectionSecrets(new VersionHolder(packet.getVersion()), Role.Client, null, new NullLogger());
            altSecrets.computeInitialKeys(originalDestinationConnectionId);
            aead = altSecrets.getPeerAead(packet.getEncryptionLevel());
        }
        else {
            log.warn("Dropping packet not using negotiated version");
            throw new InvalidPacketException("invalid version");
        }
        return aead;
    }

    /**
     * Sets the original destination connection id. This will be needed when a Retry packet is received:
     * https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets:
     * "The connection ID used with HKDF-Expand-Label is the Destination Connection ID in the Initial packet sent by the
     *  client. This will be a randomly selected value unless the client creates the Initial packet after receiving a
     *  Retry packet, where the Destination Connection ID is selected by the server."
     * @param originalDestinationConnectionId
     */
    public void setOriginalDestinationConnectionId(byte[] originalDestinationConnectionId) {
        this.originalDestinationConnectionId = originalDestinationConnectionId;
    }
}
