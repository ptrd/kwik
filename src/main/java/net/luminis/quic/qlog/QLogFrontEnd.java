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
import net.luminis.quic.qlog.event.*;

import java.time.Instant;


public class QLogFrontEnd implements QLog {

    private final QLogBackEnd qlogBackEnd;
    private final byte[] originalDcid;


    public QLogFrontEnd(byte[] originalDestinationConnectionId) {
        originalDcid = originalDestinationConnectionId;
        qlogBackEnd = new QLogBackEnd();
    }

    @Override
    public void emitConnectionCreatedEvent(Instant created) {
        qlogBackEnd.getQueue().add(new ConnectionCreatedEvent(originalDcid, created));
    }

    @Override
    public void emitPacketSentEvent(QuicPacket packet, Instant sent) {
        qlogBackEnd.getQueue().add(new PacketSentEvent(originalDcid, packet, sent));
    }

    @Override
    public void emitPacketReceivedEvent(QuicPacket packet, Instant received) {
        qlogBackEnd.getQueue().add(new PacketReceivedEvent(originalDcid, packet, received));
    }

    @Override
    public void emitConnectionTerminatedEvent() {
        qlogBackEnd.getQueue().add(new ConnectionTerminatedEvent(originalDcid));
    }

    @Override
    public void emitCongestionControlMetrics(long congestionWindow, long bytesInFlight) {
        qlogBackEnd.getQueue().add(new CongestionControlMetricsEvent(originalDcid, congestionWindow, bytesInFlight, Instant.now()));
    }

}
