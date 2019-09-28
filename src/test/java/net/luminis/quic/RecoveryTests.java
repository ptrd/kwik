/*
 * Copyright © 2019 Peter Doornbosch
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
package net.luminis.quic;

import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public abstract class RecoveryTests {

    byte[] srcCid = new byte[] { 0x01, 0x02, 0x03, 0x04 };
    byte[] destCid = new byte[] { 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    QuicPacket createPacket(int packetNumber, QuicFrame frame) {
        ShortHeaderPacket packet = new ShortHeaderPacket(Version.getDefault(), new byte[0], frame);
        packet.packetNumber = packetNumber;
        return packet;
    }

    QuicPacket createPacket(int packetNumber) {
        return createPacket(packetNumber, new MaxDataFrame(1024));
    }

    List<QuicPacket> createPackets(int... packetNumbers) {
        List<QuicPacket> packets = new ArrayList<>();
        for (int packetNumber: packetNumbers) {
            ShortHeaderPacket packet = new ShortHeaderPacket(Version.getDefault(), new byte[0], new MaxDataFrame(1024));
            packet.packetNumber = packetNumber;
            packets.add(packet);
        }
        return packets;
    }

    QuicPacket createCryptoPacket(int packetNumber) {
        LongHeaderPacket packet = new InitialPacket(Version.getDefault(), srcCid, destCid, null, new CryptoFrame());
        packet.packetNumber = packetNumber;
        return packet;
    }

    // For debugging recovery tests....
    String timeNow() {
        LocalTime localTimeNow = LocalTime.from(Instant.now().atZone(ZoneId.systemDefault()));
        DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("mm:ss.SSS");
        return timeFormatter.format(localTimeNow);
    }
}
