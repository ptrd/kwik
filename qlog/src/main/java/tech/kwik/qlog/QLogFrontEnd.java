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
package tech.kwik.qlog;

import tech.kwik.core.log.QLog;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.qlog.event.*;

import java.io.File;
import java.time.Instant;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Queue;
import java.util.Random;

/**
 * Entrypoint of the QLog module. Collects qlog events and processes them asynchronously.
 * Note that a QLOG log file will only be written if the environment variable "QLOGDIR" is set.
 */
public class QLogFrontEnd implements QLog {

    private static Random randomGenerator = new Random();

    private final byte[] originalDcid;
    private final Queue<QLogEvent> eventQueue;
    private final long connectionHandle;

    public QLogFrontEnd(byte[] originalDestinationConnectionId) {
        originalDcid = originalDestinationConnectionId;
        String qlogdirEnvVar = System.getenv("QLOGDIR");
        if (qlogdirEnvVar != null && !qlogdirEnvVar.isBlank()) {
            connectionHandle = randomGenerator.nextLong();
            eventQueue = QLogBackEnd.getInstance().getQueue();
            File qlogDir = new File(qlogdirEnvVar);
            if (!qlogDir.exists()) {
                qlogDir.mkdirs();
            }
        }
        else {
            connectionHandle = -1;
            eventQueue = new NullQueue();
        }
    }

    @Override
    public void emitConnectionCreatedEvent(Instant created) {
        eventQueue.add(new ConnectionCreatedEvent(connectionHandle, originalDcid, created));
    }

    @Override
    public void emitPacketSentEvent(QuicPacket packet, Instant sent) {
        eventQueue.add(new PacketSentEvent(connectionHandle, originalDcid, packet, sent));
    }

    @Override
    public void emitPacketSentEvent(List<QuicPacket> packets, Instant sent) {
        packets.stream().forEach(packet -> eventQueue.add(new PacketSentEvent(connectionHandle, originalDcid, packet, sent)));
    }

    @Override
    public void emitPacketReceivedEvent(QuicPacket packet, Instant received) {
        eventQueue.add(new PacketReceivedEvent(connectionHandle, originalDcid, packet, received));
    }

    @Override
    public void emitPacketLostEvent(QuicPacket packet, Instant received) {
        eventQueue.add(new PacketLostEvent(connectionHandle, originalDcid, packet, received));
    }

    @Override
    public void emitConnectionTerminatedEvent() {
        eventQueue.add(new ConnectionTerminatedEvent(connectionHandle, originalDcid));
    }

    @Override
    public void emitCongestionControlMetrics(long congestionWindow, long bytesInFlight) {
        eventQueue.add(new CongestionControlMetricsEvent(connectionHandle, originalDcid, congestionWindow, bytesInFlight, Instant.now()));
    }

    @Override
    public void emitRttMetrics(int smoothedRtt, int rttVar, int latestRtt) {
        eventQueue.add(new RttMetricsEvent(connectionHandle, originalDcid, smoothedRtt, rttVar, latestRtt, Instant.now()));
    }

    @Override
    public void emitRecoveryMetrics(long congestionWindow, long bytesInFlight, int smoothedRtt, int rttVar, int latestRtt) {
        CongestionControlMetricsEvent controlMetricsEvent = new CongestionControlMetricsEvent(connectionHandle, originalDcid, congestionWindow, bytesInFlight, Instant.now());
        RttMetricsEvent rttMetricsEvent = new RttMetricsEvent(connectionHandle, originalDcid, smoothedRtt, rttVar, latestRtt, Instant.now());
        eventQueue.add(new RecoveryMetricsEvent(controlMetricsEvent, rttMetricsEvent));
    }

    @Override
    public void emitConnectionClosedEvent(Instant time) {
        eventQueue.add(new ConnectionClosedEvent(connectionHandle, originalDcid, time, ConnectionClosedEvent.Trigger.idleTimeout));
    }

    @Override
    public void emitConnectionClosedEvent(Instant time, long errorCode, String errorReason) {
        eventQueue.add(new ConnectionClosedEvent(connectionHandle, originalDcid, time, ConnectionClosedEvent.Trigger.immediateClose, errorCode, errorReason));
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
