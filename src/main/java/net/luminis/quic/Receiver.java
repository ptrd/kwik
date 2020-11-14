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
package net.luminis.quic;

import net.luminis.quic.log.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.time.Instant;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Receives UDP datagrams on separate thread and queues them for asynchronous processing.
 */
public class Receiver {

    private final QuicClientConnectionImpl connection;
    private volatile DatagramSocket socket;
    private final int maxPacketSize;
    private final Logger log;
    private final Thread receiverThread;
    private final BlockingQueue<RawPacket> receivedPacketsQueue;
    private volatile boolean isClosing = false;
    private volatile boolean changing = false;

    public Receiver(QuicClientConnectionImpl connection, DatagramSocket socket, int initialMaxPacketSize, Logger log) {
        this.connection = connection;
        this.socket = socket;
        this.maxPacketSize = initialMaxPacketSize;
        this.log = log;

        receiverThread = new Thread(() -> run(), "receiver");
        receiverThread.setDaemon(true);
        receivedPacketsQueue = new LinkedBlockingQueue<>();

        try {
            log.debug("Socket receive buffer size: " + socket.getReceiveBufferSize());
        } catch (SocketException e) {
            // Ignore
        }
    }

    public void start() {
        receiverThread.start();
    }

    public void shutdown() {
        isClosing = true;
        receiverThread.interrupt();
    }

    public RawPacket get() throws InterruptedException {
        return receivedPacketsQueue.take();
    }

    public boolean hasMore() {
        return !receivedPacketsQueue.isEmpty();
    }

    /**
     * Retrieves a received packet from the queue.
     * @param timeout    the wait timeout in seconds
     * @return
     * @throws InterruptedException
     */
    public RawPacket get(int timeout) throws InterruptedException {
        return receivedPacketsQueue.poll(timeout, TimeUnit.SECONDS);
    }

    private void run() {
        int counter = 0;

        try {
            while (! isClosing) {
                byte[] receiveBuffer = new byte[maxPacketSize + 1];
                DatagramPacket receivedPacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                try {
                    socket.receive(receivedPacket);

                    Instant timeReceived = Instant.now();
                    RawPacket rawPacket = new RawPacket(receivedPacket, timeReceived, counter++);
                    receivedPacketsQueue.add(rawPacket);
                }
                catch (SocketTimeoutException timeout) {
                    // Impossible, as no socket timeout set
                }
                catch (SocketException socketError) {
                    if (changing) {
                        // Expected
                        log.debug("Ignoring socket closed exception, because changing socket", socketError);
                        changing = false;  // Don't do it again.
                    }
                    else {
                        throw socketError;
                    }
                }
            }

            log.debug("Terminating receive loop");
        }
        catch (IOException e) {
            if (! isClosing) {
                // This is probably fatal
                log.error("IOException while receiving datagrams", e);
                connection.abortConnection(e);
            }
            else {
                log.debug("closing receiver");
            }
        }
        catch (Throwable fatal) {
            log.error("IOException while receiving datagrams", fatal);
            connection.abortConnection(fatal);
        }
    }

    public void changeAddress(DatagramSocket newSocket) {
        DatagramSocket oldSocket = socket;
        socket = newSocket;
        changing = true;
        oldSocket.close();
    }
}
