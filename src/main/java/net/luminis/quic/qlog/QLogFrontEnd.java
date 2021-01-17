/*
 * Copyright © 2020, 2021 Peter Doornbosch
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

import javax.sql.ConnectionEvent;
import java.time.Instant;
import java.util.Collection;
import java.util.Iterator;
import java.util.Queue;


public class QLogFrontEnd implements QLog {

    private final byte[] originalDcid;
    private final Queue<QLogEvent> eventQueue;


    public QLogFrontEnd(byte[] originalDestinationConnectionId) {
        originalDcid = originalDestinationConnectionId;
        String qlogdirEnvVar = System.getenv("QLOGDIR");
        if (qlogdirEnvVar != null && !qlogdirEnvVar.isBlank()) {
            eventQueue = new QLogBackEnd().getQueue();
        }
        else {
            eventQueue = new NullQueue();
        }
    }

    @Override
    public void emitConnectionCreatedEvent(Instant created) {
        eventQueue.add(new ConnectionCreatedEvent(originalDcid, created));
    }

    @Override
    public void emitPacketSentEvent(QuicPacket packet, Instant sent) {
        eventQueue.add(new PacketSentEvent(originalDcid, packet, sent));
    }

    @Override
    public void emitPacketReceivedEvent(QuicPacket packet, Instant received) {
        eventQueue.add(new PacketReceivedEvent(originalDcid, packet, received));
    }

    @Override
    public void emitConnectionTerminatedEvent() {
        eventQueue.add(new ConnectionTerminatedEvent(originalDcid));
    }

    @Override
    public void emitCongestionControlMetrics(long congestionWindow, long bytesInFlight) {
        eventQueue.add(new CongestionControlMetricsEvent(originalDcid, congestionWindow, bytesInFlight, Instant.now()));
    }

    @Override
    public void emitConnectionClosedEvent(Instant time) {
        eventQueue.add(new ConnectionClosedEvent(originalDcid, time, ConnectionClosedEvent.Trigger.idleTimeout));
    }

    @Override
    public void emitConnectionClosedEvent(Instant time, int transportErrorCode, String errorReason) {
        eventQueue.add(new ConnectionClosedEvent(originalDcid, time, ConnectionClosedEvent.Trigger.immediateClose, transportErrorCode, errorReason));
    }

    private static class NullQueue implements Queue<QLogEvent> {
        @Override
        public int size() {
            return 0;
        }

        @Override
        public boolean isEmpty() {
            return false;
        }

        @Override
        public boolean contains(Object o) {
            return false;
        }

        @Override
        public Iterator<QLogEvent> iterator() {
            return null;
        }

        @Override
        public Object[] toArray() {
            return new Object[0];
        }

        @Override
        public <T> T[] toArray(T[] a) {
            return null;
        }

        @Override
        public boolean add(QLogEvent qLogEvent) {
            return false;
        }

        @Override
        public boolean remove(Object o) {
            return false;
        }

        @Override
        public boolean containsAll(Collection<?> c) {
            return false;
        }

        @Override
        public boolean addAll(Collection<? extends QLogEvent> c) {
            return false;
        }

        @Override
        public boolean removeAll(Collection<?> c) {
            return false;
        }

        @Override
        public boolean retainAll(Collection<?> c) {
            return false;
        }

        @Override
        public void clear() {

        }

        @Override
        public boolean offer(QLogEvent qLogEvent) {
            return false;
        }

        @Override
        public QLogEvent remove() {
            return null;
        }

        @Override
        public QLogEvent poll() {
            return null;
        }

        @Override
        public QLogEvent element() {
            return null;
        }

        @Override
        public QLogEvent peek() {
            return null;
        }
    }
}
