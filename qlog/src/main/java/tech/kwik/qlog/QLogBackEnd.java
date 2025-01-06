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
package tech.kwik.qlog;

import tech.kwik.qlog.event.ConnectionCreatedEvent;
import tech.kwik.qlog.event.ConnectionTerminatedEvent;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;


public class QLogBackEnd {

    private final BlockingQueue<QLogEvent> queue;
    private Map<Cid, ConnectionQLog> connections;

    public QLogBackEnd() {
        this.queue = new LinkedBlockingQueue<>();
        this.connections = new ConcurrentHashMap<>();

        Thread qlogWriterThread = new Thread(() -> generateConnectionLog());
        qlogWriterThread.setDaemon(true);
        qlogWriterThread.setPriority(Thread.MIN_PRIORITY);
        qlogWriterThread.setName("qlog-writer");
        qlogWriterThread.start();
    }

    public Queue<QLogEvent> getQueue() {
        return queue;
    }

    private void generateConnectionLog() {
        while (true) {
            try {
                QLogEvent event = queue.poll(63_000, TimeUnit.MILLISECONDS);   // Should be greater than max idle-timeout
                if (event != null) {
                    Cid key = new Cid(event.getCid());
                    if (event instanceof ConnectionCreatedEvent) {
                        connections.put(key, new ConnectionQLog(event));
                    }

                    ConnectionQLog connectionQLog = connections.get(key);
                    if (connectionQLog != null) {
                        event.accept(connectionQLog);
                    }
                    else {
                        continue;
                    }

                    if (event instanceof ConnectionTerminatedEvent) {
                        connections.remove(key);
                    }
                }
                else {
                    connections.values().stream().forEach(log -> log.close());
                    connections.clear();
                }
            }
            catch (IOException | InterruptedException e) {
            }
        }
    }

    private static final class Cid {
        private final byte[] cid;
        private final int hash;

        public Cid(byte[] cid) {
            this.cid = cid;
            hash = Arrays.hashCode(cid);
        }

        @Override
        public int hashCode() {
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof Cid) {
                return Arrays.equals(cid, ((Cid) obj).cid);
            }
            else {
                return false;
            }
        }
    }
}
