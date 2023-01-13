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
import net.luminis.quic.qlog.event.*;

import javax.sql.ConnectionEvent;
import java.io.File;
import java.time.Instant;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Queue;

/**
 * Entrypoint of the QLog module. Collects qlog events and processes them asynchronously.
 * Note that a QLOG log file will only be written if the environment variable "QLOGDIR" is set.
 */
public class QLogFrontEnd implements QLog {

    private final byte[] originalDcid;
    private final Queue<QLogEvent> eventQueue;


    public QLogFrontEnd(byte[] originalDestinationConnectionId) {
        originalDcid = originalDestinationConnectionId;
        String qlogdirEnvVar = System.getenv("QLOGDIR");
        if (qlogdirEnvVar != null && !qlogdirEnvVar.isBlank()) {
            eventQueue = new QLogBackEnd().getQueue();
            File qlogDir = new File(qlogdirEnvVar);
            if (!qlogDir.exists()) {
                qlogDir.mkdirs();
            }
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
    public void emitPacketSentEvent(List<QuicPacket> packets, Instant sent) {
        packets.stream().forEach(packet -> eventQueue.add(new PacketSentEvent(originalDcid, packet, sent)));
    }

    @Override
    public void emitPacketReceivedEvent(QuicPacket packet, Instant received) {
        eventQueue.add(new PacketReceivedEvent(originalDcid, packet, received));
    }

    @Override
    public void emitPacketLostEvent(QuicPacket packet, Instant received) {
        eventQueue.add(new PacketLostEvent(originalDcid, packet, received));
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
