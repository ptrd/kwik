/*
 * Copyright © 2019, 2020 Peter Doornbosch
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
package net.luminis.quic.qlog;

import net.luminis.quic.packet.QuicPacket;

import java.time.Instant;


public class QLogFrontEnd implements QLog {

    private final QLogBackEnd qlogBackEnd;
    private final byte[] originalDcid;


    public QLogFrontEnd(byte[] originalDestinationConnectionId) {
        originalDcid = originalDestinationConnectionId;
        qlogBackEnd = new QLogBackEnd();
    }

    @Override
    public void emitConnectionCreatedEvent() {
        qlogBackEnd.getQueue().add(new QLogEvent(originalDcid));
    }

    @Override
    public void emitPacketSentEvent(QuicPacket packet, Instant sent) {
        qlogBackEnd.getQueue().add(new QLogEvent(originalDcid, QLogEvent.Type.PacketSent, packet, sent));
    }

    @Override
    public void emitPacketReceivedEvent(QuicPacket packet, Instant received) {
        qlogBackEnd.getQueue().add(new QLogEvent(originalDcid, QLogEvent.Type.PacketReceived, packet, received));
    }

    @Override
    public void emitConnectionTerminatedEvent() {
        qlogBackEnd.getQueue().add(new QLogEvent(originalDcid, QLogEvent.Type.EndConnection));
    }
}
