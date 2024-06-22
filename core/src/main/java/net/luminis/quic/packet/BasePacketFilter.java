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
package net.luminis.quic.packet;

import net.luminis.quic.log.Logger;
import net.luminis.quic.log.NullLogger;

public abstract class BasePacketFilter implements PacketFilter {

    private final PacketFilter next;
    private final Logger log;

    public BasePacketFilter(PacketFilter next) {
        this.next = next;
        log = new NullLogger();
    }

    public BasePacketFilter(PacketFilter next, Logger log) {
        this.next = next;
        this.log = log != null ? log : new NullLogger();
    }

    public BasePacketFilter(BasePacketFilter next) {
        this.next = next;
        this.log = next.logger();
    }

    public void next(QuicPacket packet, PacketMetaData metaData) {
        next.processPacket(packet, metaData);
    }

    protected void discard(QuicPacket packet, String reason) {
        logger().debug("Discarding packet " + packet + ": " + reason);
    }

    protected Logger logger() {
        return log;
    }
}
