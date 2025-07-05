/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.log;

import tech.kwik.core.packet.QuicPacket;

import java.time.Instant;
import java.util.List;


public class NullQLog implements QLog {

    @Override
    public void emitConnectionCreatedEvent(Instant created) {}

    @Override
    public void emitPacketSentEvent(QuicPacket packet, Instant sent) {}

    @Override
    public void emitPacketSentEvent(List<QuicPacket> packets, Instant sent) {}

    @Override
    public void emitPacketReceivedEvent(QuicPacket packet, Instant received) {}

    @Override
    public void emitPacketLostEvent(QuicPacket packet, Instant received) {}

    @Override
    public void emitConnectionTerminatedEvent() {}

    @Override
    public void emitCongestionControlMetrics(long congestionWindow, long bytesInFlight) {}

    @Override
    public void emitRttMetrics(int smoothedRtt, int rttVar, int latestRtt) {}

    @Override
    public void emitConnectionClosedEvent(Instant created) {}

    @Override
    public void emitConnectionClosedEvent(Instant time, long errorCode, String errorReason) {}
}
