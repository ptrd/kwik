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
package net.luminis.quic.server;

import net.luminis.quic.core.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.BaseDatagramFilter;
import net.luminis.quic.packet.DatagramFilter;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.LongHeaderPacket;
import net.luminis.quic.packet.PacketMetaData;

import java.nio.ByteBuffer;

/**
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-initial-datagram-size
 * "A server MUST discard an Initial packet that is carried in a UDP datagram with a payload that is smaller than the
 *  smallest allowed maximum datagram size of 1200 bytes."
 */
public class InitialPacketMinimumSizeFilter extends BaseDatagramFilter {

    public InitialPacketMinimumSizeFilter(Logger log, DatagramFilter next) {
        super(next, log);
    }

    @Override
    public void processDatagram(ByteBuffer data, PacketMetaData metaData) {
        data.mark();
        int datagramLength = data.limit() - data.position();
        byte flags = data.get();
        Version longHeaderPacketVersion = new Version(data.getInt());  // Field only represents version when long header packet
        data.rewind();

        if (LongHeaderPacket.isLongHeaderPacket(flags, longHeaderPacketVersion)
                && InitialPacket.isInitial((flags & 0x30) >> 4, longHeaderPacketVersion)
                && datagramLength < 1200) {
            discard(data, metaData, "Initial packet is smaller than minimum size");
        }
        else {
            next(data, metaData);
        }
    }
}
