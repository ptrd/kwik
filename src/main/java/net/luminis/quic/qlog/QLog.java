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
package net.luminis.quic.qlog;

import net.luminis.quic.packet.QuicPacket;

import java.time.Instant;
import java.util.List;


/**
 * Defines the methods for emitting QLog events.
 *
 * See
 * https://tools.ietf.org/html/draft-marx-qlog-main-schema-02
 * and
 * https://tools.ietf.org/html/draft-marx-qlog-event-definitions-quic-h3-02
 */
public interface QLog {

    void emitConnectionCreatedEvent(Instant created);

    void emitPacketSentEvent(QuicPacket packet, Instant sent);

    void emitPacketSentEvent(List<QuicPacket> packets, Instant sent);

    void emitPacketReceivedEvent(QuicPacket packet, Instant received);

    void emitPacketLostEvent(QuicPacket packet, Instant received);

    void emitConnectionTerminatedEvent();

    void emitCongestionControlMetrics(long congestionWindow, long bytesInFlight);

    void emitConnectionClosedEvent(Instant time);

    void emitConnectionClosedEvent(Instant time, int transportErrorCode, String errorReason);
}
