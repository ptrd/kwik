/*
 * Copyright © 2020 Peter Doornbosch
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
package net.luminis.quic.send;

import net.luminis.quic.AckGenerator;
import net.luminis.quic.EncryptionLevel;
import net.luminis.quic.Version;
import net.luminis.quic.frame.Padding;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.QuicPacket;

import java.util.Optional;


/**
 * Assembles initial packets, based on "send requests" that are previously queued.
 * Overrides the generic based class, because Initial Packets may include a token.
 * https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-8.1.3
 * "The client MUST include the token in all Initial packets it sends,..."
 */
public class InitialPacketAssembler extends PacketAssembler {

    protected byte[] initialToken;

    public InitialPacketAssembler(Version version, int maxPacketSize, SendRequestQueue requestQueue, AckGenerator ackGenerator) {
        super(version, EncryptionLevel.Initial, maxPacketSize, requestQueue, ackGenerator);
    }

    @Override
    protected QuicPacket createPacket(byte[] sourceConnectionId, byte[] destinationConnectionId, QuicFrame frame) {
        InitialPacket packet = new InitialPacket(quicVersion, sourceConnectionId, destinationConnectionId, initialToken, frame);
        packet.setPacketNumber(nextPacketNumber());
        return packet;
    }

    public void setInitialToken(byte[] initialToken) {
        this.initialToken = initialToken;
    }
}

