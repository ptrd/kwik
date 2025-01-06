/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.recovery;

import tech.kwik.core.impl.Version;
import tech.kwik.core.frame.CryptoFrame;
import tech.kwik.core.frame.MaxDataFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.packet.HandshakePacket;
import tech.kwik.core.packet.InitialPacket;
import tech.kwik.core.packet.LongHeaderPacket;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.packet.ShortHeaderPacket;
import tech.kwik.core.test.FieldSetter;

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
        setPacketNumber(packet, packetNumber);
        return packet;
    }

    QuicPacket createPacket(int packetNumber) {
        return createPacket(packetNumber, new MaxDataFrame(1024));
    }

    List<QuicPacket> createPackets(int... packetNumbers) {
        List<QuicPacket> packets = new ArrayList<>();
        for (int packetNumber: packetNumbers) {
            ShortHeaderPacket packet = new ShortHeaderPacket(Version.getDefault(), new byte[0], new MaxDataFrame(1024));
            setPacketNumber(packet, packetNumber);
            packets.add(packet);
        }
        return packets;
    }

    QuicPacket createHandshakePacket(int packetNumber, QuicFrame... frames) {
        LongHeaderPacket packet = new HandshakePacket(Version.getDefault(), srcCid, destCid, frames[0]);
        for (int i = 1; i < frames.length; i++) {
            packet.addFrame(frames[i]);
        }
        setPacketNumber(packet, packetNumber);
        return packet;
    }

    QuicPacket createCryptoPacket(int packetNumber) {
        LongHeaderPacket packet = new InitialPacket(Version.getDefault(), srcCid, destCid, null, new CryptoFrame());
        setPacketNumber(packet, packetNumber);
        return packet;
    }

    void setPacketNumber(QuicPacket packet, int packetNumber) {
        try {
            FieldSetter.setField(packet, QuicPacket.class.getDeclaredField("packetNumber"), packetNumber);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    // For debugging recovery tests....
    String timeNow() {
        LocalTime localTimeNow = LocalTime.from(Instant.now().atZone(ZoneId.systemDefault()));
        DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("mm:ss.SSS");
        return timeFormatter.format(localTimeNow);
    }
}
