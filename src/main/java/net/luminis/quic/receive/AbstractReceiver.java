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
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.time.Instant;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * Base class with implementations for common methods.
 */
public abstract class AbstractReceiver implements Receiver {

    protected final Logger log;
    private final Predicate<DatagramPacket> packetFilter;
    protected final Consumer<Throwable> abortCallback;
    protected final BlockingQueue<RawPacket> receivedPacketsQueue;
    protected volatile boolean isClosing;

    public AbstractReceiver(Logger log, Predicate<DatagramPacket> packetFilter, Consumer<Throwable> abortCallback) {
        this.log = log;
        this.packetFilter = packetFilter;
        this.abortCallback = abortCallback;

        receivedPacketsQueue = new LinkedBlockingQueue<>();
    }

    @Override
    public RawPacket get() throws InterruptedException {
        return receivedPacketsQueue.take();
    }

    /**
     * Retrieves a received packet from the queue.
     * @param timeout    the wait timeout in seconds
     * @return
     * @throws InterruptedException
     */
    @Override
    public RawPacket get(int timeout) throws InterruptedException {
        return receivedPacketsQueue.poll(timeout, TimeUnit.SECONDS);
    }

    @Override
    public boolean hasMore() {
        return !receivedPacketsQueue.isEmpty();
    }

    protected void runSocketReceiveLoop(DatagramSocket socket) {
        log.info("Start listen loop on port " + socket.getLocalPort());
        int counter = 0;

        try {
            while (! isClosing) {
                byte[] receiveBuffer = new byte[MAX_DATAGRAM_SIZE];
                DatagramPacket receivedPacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                try {
                    socket.receive(receivedPacket);

                    if (packetFilter.test(receivedPacket)) {
                        Instant timeReceived = Instant.now();
                        RawPacket rawPacket = new RawPacket(receivedPacket, timeReceived, (InetSocketAddress) socket.getLocalSocketAddress());
                        receivedPacketsQueue.add(rawPacket);
                    }
                }
                catch (SocketTimeoutException timeout) {
                    // Impossible, as no socket timeout set
                }
            }

            log.debug("Terminating receive loop");
        }
        catch (IOException e) {
            if (isFatal(e)) {
                log.error("IOException while receiving datagrams", e);
                abortCallback.accept(e);
            }
            else {
                log.debug("closing receiver");
            }
        }
        catch (Throwable fatal) {
            log.error("IOException while receiving datagrams", fatal);
            abortCallback.accept(fatal);
        }
    }

    protected boolean isFatal(IOException ioException) {
        return !isClosing;
    }
}
