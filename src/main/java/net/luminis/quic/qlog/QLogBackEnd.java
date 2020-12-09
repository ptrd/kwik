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

import java.io.IOException;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static net.luminis.quic.qlog.QLogEvent.Type.EndConnection;
import static net.luminis.quic.qlog.QLogEvent.Type.StartConnection;


public class QLogBackEnd {

    private final BlockingQueue<QLogEvent> queue;
    private Map<byte[], ConnectionQLog> connections;

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
                QLogEvent event = queue.poll(10_000, TimeUnit.MILLISECONDS);
                if (event == null) {
                    connections.values().stream().forEach(log -> log.close());
                    connections.clear();
                } else {
                    if (event.getType() == StartConnection) {
                        connections.put(event.getCid(), new ConnectionQLog(event.getCid()));
                    }
                    else if (event.getType() == EndConnection) {
                        connections.get(event.getCid()).process(event);
                        connections.remove(event.getCid());
                    }
                    else {
                        connections.get(event.getCid()).process(event);
                    }
                }
            }
            catch (IOException | InterruptedException e) {
            }
        }

    }




}
