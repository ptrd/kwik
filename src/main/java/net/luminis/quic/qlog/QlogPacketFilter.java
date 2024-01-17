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
package net.luminis.quic.qlog;

import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.BasePacketFilter;
import net.luminis.quic.packet.PacketFilter;
import net.luminis.quic.packet.QuicPacket;

import java.time.Instant;

public class QlogPacketFilter extends BasePacketFilter {

    public QlogPacketFilter(PacketFilter next, Logger log) {
        super(next, log);
    }

    public QlogPacketFilter(BasePacketFilter next) {
        super(next);
    }

    @Override
    public void processPacket(Instant timeReceived, QuicPacket packet) {
        logger().getQLog().emitPacketReceivedEvent(packet, timeReceived);
        next(timeReceived, packet);
    }
}
