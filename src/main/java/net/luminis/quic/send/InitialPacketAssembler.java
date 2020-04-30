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


public class InitialPacketAssembler extends PacketAssembler {

    protected byte[] initialToken;

    public InitialPacketAssembler(Version version, int maxPacketSize, SendRequestQueue requestQueue, AckGenerator ackGenerator) {
        super(version, EncryptionLevel.Initial, maxPacketSize, requestQueue, ackGenerator);
    }

    @Override
    QuicPacket assemble(int remainingCwndSize, long packetNumber, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        QuicPacket packet = super.assemble(remainingCwndSize, packetNumber, sourceConnectionId, destinationConnectionId);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-14
        // "A client MUST expand the payload of all UDP datagrams carrying Initial packets to
        // at least 1200 bytes, by adding PADDING frames to the Initial packet or ..."
        int requiredPadding = 1200 - packet.estimateLength();
        packet.addFrame(new Padding(requiredPadding));
        return packet;
    }

    @Override
    protected QuicPacket createPacket(byte[] sourceConnectionId, byte[] destinationConnectionId, QuicFrame frame) {
        return new InitialPacket(quicVersion, sourceConnectionId, destinationConnectionId, initialToken, frame);
    }

    public void setInitialToken(byte[] initialToken) {
        this.initialToken = initialToken;
    }
}

