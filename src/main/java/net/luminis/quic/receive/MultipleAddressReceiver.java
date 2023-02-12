/*
 * Copyright © 2023 Peter Doornbosch
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
package net.luminis.quic.receive;

import net.luminis.quic.log.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketTimeoutException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Receiver that can listen on multiple UDP` ports at the same time.
 * The order in which received packets are made available through the get methods is more or less in order of when
 * they are received, but this order is not strictly maintained (so a caller might see two packets that are received on
 * different orders in reverse order of when they were received by the network interface).
 */
public class MultipleAddressReceiver extends AbstractReceiver {

    private final List<DatagramSocket> sockets;
    private final List<Thread> threads;

    public MultipleAddressReceiver(Logger log, Consumer<Throwable> abortCallback) {
        super(log, abortCallback);
        sockets = new CopyOnWriteArrayList<>();
        threads = new CopyOnWriteArrayList<>();
    }

    @Override
    public void start() {
        // Intentionally doing nothing: a listen thread will be started when a socket is added
    }

    private void start(DatagramSocket socket) {
        Thread receiverThread = new Thread(() -> runSocketReceiveLoop(socket), "receiver" + threads.size());
        receiverThread.setDaemon(true);
        threads.add(receiverThread);
        receiverThread.start();
    }

    @Override
    public void shutdown() {
        isClosing = true;
        threads.forEach(t -> t.interrupt());
    }

    public synchronized void addSocket(DatagramSocket socket) {
        // Sync'd to ensure that lists of sockets and threads always match
        sockets.add(socket);
        start(socket);
    }

    public synchronized void removeSocket(DatagramSocket socket) {
        // Sync'd to ensure that lists of sockets and threads always match
        int index = sockets.indexOf(socket);
        if (index >= 0) {
            DatagramSocket removedSocket = sockets.remove(index);
            removedSocket.close();
            threads.remove(index);
        }
    }

    @Override
    protected boolean isFatal(IOException ioException) {
        return !isClosing && threads.contains(Thread.currentThread());
    }
}
