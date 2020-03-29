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
package net.luminis.quic.recovery;

import net.luminis.quic.packet.PacketInfo;
import net.luminis.quic.packet.QuicPacket;

import java.time.Instant;
import java.util.function.Consumer;


class PacketStatus extends PacketInfo {
    boolean lost;
    boolean acked;

    public PacketStatus(Instant sent, QuicPacket packet, Consumer<QuicPacket> lostPacketCallback) {
        super(sent, packet, lostPacketCallback);
    }

    public String status() {
        if (acked) {
            return "Acked";
        } else if (lost) {
            return "Resent";
        } else {
            return "-";
        }
    }

    @Override
    public String toString() {
        return "Packet "
                + packet().getEncryptionLevel().name().charAt(0) + "|"
                + (packet().getPacketNumber() >= 0 ? packet().getPacketNumber() : ".") + "|"
                + " " + "|"
                + packet().getSize() + "|"
                + status();
    }
}

