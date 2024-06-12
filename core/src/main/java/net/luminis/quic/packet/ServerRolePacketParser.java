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
package net.luminis.quic.packet;

import net.luminis.quic.impl.InvalidPacketException;
import net.luminis.quic.impl.QuicConnectionImpl;
import net.luminis.quic.impl.Role;
import net.luminis.quic.impl.VersionHolder;
import net.luminis.quic.crypto.Aead;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.crypto.MissingKeysException;
import net.luminis.quic.generic.InvalidIntegerEncodingException;
import net.luminis.quic.generic.VariableLengthInteger;
import net.luminis.quic.log.Logger;

import java.nio.ByteBuffer;
import java.util.function.Supplier;

import static net.luminis.quic.core.EncryptionLevel.*;
import static net.luminis.quic.impl.QuicConnectionImpl.VersionNegotiationStatus.VersionChangeUnconfirmed;

/**
 * Packet parser for endpoint that has server role.
 */
public class ServerRolePacketParser extends PacketParser {

    private final boolean retryRequired;
    private final Supplier<QuicConnectionImpl.VersionNegotiationStatus> versionNegotiationStatusSupplier;

    public ServerRolePacketParser(ConnectionSecrets secrets, VersionHolder quicVersion, int cidLength, boolean retryRequired,
                                  PacketFilter processor, Supplier<QuicConnectionImpl.VersionNegotiationStatus> versionNegotiationStatusSupplier, Logger logger) {
        super(secrets, quicVersion, cidLength, processor, Role.Server, logger);
        this.retryRequired = retryRequired;
        this.versionNegotiationStatusSupplier = versionNegotiationStatusSupplier;
    }

    protected Aead getAead(QuicPacket packet, ByteBuffer data) throws MissingKeysException, InvalidPacketException {
        Aead aead;

        if (retryRequired && packet instanceof InitialPacket) {
            // Check whether the packet has a (retry) token
            data.mark();
            int destCidLength = data.get(5) & 0xff;
            int srcCidLength = data.get(6 + destCidLength) & 0xff;
            data.position(7 + destCidLength + srcCidLength);
            int tokenLength;
            try {
                tokenLength = VariableLengthInteger.parse(data);
            } catch (InvalidIntegerEncodingException e) {
                throw new InvalidPacketException();
            }
            data.reset();
            if (tokenLength == 0) {
                // If the packet has no token, it uses the secrets based on the original destination connection id.
                return connectionSecrets.getOriginalClientInitialAead();
            }
        }

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
        else if (packet.getEncryptionLevel() == ZeroRTT) {
            // https://www.rfc-editor.org/rfc/rfc9369.html#name-compatible-negotiation-requ
            // "Servers can accept 0-RTT and then process 0-RTT packets from the original version."
            aead = connectionSecrets.getPeerAead(packet.getEncryptionLevel());
        }
        else if (packet.getEncryptionLevel() == Initial && versionNegotiationStatusSupplier.get() == VersionChangeUnconfirmed) {
            // https://www.rfc-editor.org/rfc/rfc9369.html#name-compatible-negotiation-requ
            // "The server MUST NOT discard its original version Initial receive keys until it successfully processes
            //  a packet with the negotiated version."
            aead = connectionSecrets.getInitialPeerSecretsForVersion(packet.getVersion());
        }
        else {
            log.warn("Dropping packet not using negotiated version");
            throw new InvalidPacketException("invalid version");
        }
        return aead;
    }

}
