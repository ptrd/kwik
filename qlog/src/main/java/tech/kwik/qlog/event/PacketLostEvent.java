/*
 * Copyright © 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.qlog.event;

import tech.kwik.core.packet.QuicPacket;

import java.time.Instant;

/**
 * QLog QUIC event recovery:packet_lost
 * See https://www.ietf.org/archive/id/draft-ietf-quic-qlog-quic-events-01.html#name-packet_lost
 */
public class PacketLostEvent extends PacketEvent {

    public PacketLostEvent(long connectionHandle, byte[] cid, QuicPacket packet, Instant time) {
        super(connectionHandle, cid, packet, time);
    }

    @Override
    public void accept(QLogEventProcessor processor) {
        processor.process(this);
    }
}
