/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.send;

import tech.kwik.core.ack.AckGenerator;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.packet.InitialPacket;
import tech.kwik.core.packet.QuicPacket;

import java.util.Optional;


/**
 * Assembles initial packets, based on "send requests" that are previously queued.
 * Overrides the generic based class, because Initial Packets may include a token.
 * https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-8.1.3
 * "The client MUST include the token in all Initial packets it sends,..."
 */
public class InitialPacketAssembler extends PacketAssembler {

    protected byte[] initialToken;

    public InitialPacketAssembler(VersionHolder version, SendRequestQueue requestQueue, AckGenerator ackGenerator) {
        super(version, EncryptionLevel.Initial, requestQueue, ackGenerator);
    }

    @Override
    Optional<SendItem> assemble(int remainingCwndSize, int availablePacketSize, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        if (availablePacketSize < 1200) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-14
            // "A client MUST expand the payload of all UDP datagrams carrying Initial packets to at least the smallest
            //  allowed maximum datagram size of 1200 bytes... "
            // "Similarly, a server MUST expand the payload of all UDP datagrams carrying ack-eliciting Initial packets
            //  to at least the smallest allowed maximum datagram size of 1200 bytes."
            // Note that in case of an initial packet, the availablePacketSize equals the maximum datagram size; even
            // when different packets are coalesced, the initial packet is always the first that is assembled.
            return Optional.empty();
        }
        return super.assemble(remainingCwndSize, availablePacketSize, sourceConnectionId, destinationConnectionId);
    }

    @Override
    protected QuicPacket createPacket(byte[] sourceConnectionId, byte[] destinationConnectionId) {
        InitialPacket packet = new InitialPacket(quicVersion.getVersion(), sourceConnectionId, destinationConnectionId, initialToken, (QuicFrame) null);
        packet.setPacketNumber(nextPacketNumber());
        return packet;
    }

    public void setInitialToken(byte[] initialToken) {
        this.initialToken = initialToken;
    }
}

