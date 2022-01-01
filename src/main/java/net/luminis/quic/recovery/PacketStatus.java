/*
 * Copyright © 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic.recovery;

import net.luminis.quic.packet.PacketInfo;
import net.luminis.quic.packet.QuicPacket;

import java.time.Instant;
import java.util.function.Consumer;


class PacketStatus extends PacketInfo {

    private boolean lost;
    private boolean acked;

    public PacketStatus(Instant sent, QuicPacket packet, Consumer<QuicPacket> lostPacketCallback) {
        super(sent, packet, lostPacketCallback);
    }

    public synchronized boolean acked() {
        return acked;
    }

    public synchronized boolean setAcked() {
        if (!acked && !lost) {
            acked = true;
            return true;
        }
        else {
            return false;
        }
    }

    public synchronized boolean inFlight() {
        return !acked && !lost;
    }

    public synchronized boolean setLost() {
        if (!acked && !lost) {
            lost = true;
            return true;
        }
        else {
            return false;
        }
    }

    public String status() {
        if (acked) {
            return "Acked";
        } else if (lost) {
            return "Lost";
        } else {
            return "Inflight";
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

