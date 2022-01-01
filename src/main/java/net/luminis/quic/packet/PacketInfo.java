/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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

import java.time.Instant;
import java.util.function.Consumer;

public class PacketInfo {

    final Instant timeSent;
    final QuicPacket packet;
    final Consumer<QuicPacket> lostPacketCallback;

    public PacketInfo(Instant sent, QuicPacket packet, Consumer<QuicPacket> lostPacketCallback) {
        this.timeSent = sent;
        this.packet = packet;
        this.lostPacketCallback = lostPacketCallback;
    }

    public Instant timeSent() {
        return timeSent;
    }

    public QuicPacket packet() {
        return packet;
    }

    public Consumer lostPacketCallback() {
        return lostPacketCallback;
    }

    @Override
    public String toString() {
        return "Packet "
            + packet.getEncryptionLevel().name().charAt(0) + "|"
            + (packet.packetNumber >= 0? packet.packetNumber: ".");
    }

}

