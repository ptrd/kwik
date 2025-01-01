/*
 * Copyright © 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package net.luminis.quic.server.impl;

import net.luminis.quic.packet.DatagramParserFilter;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.PacketMetaData;
import net.luminis.quic.util.Bytes;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Proxy for server connection that ensures that all processing of received datagrams is executed on a separate thread.
 * This implementation creates a new thread for each connection, so the methods that execute as part of processing
 * received datagrams can use thread-confinement strategy for concurrency control.
 */
public class ServerConnectionThread implements ServerConnectionProxy {

    private final ServerConnectionImpl serverConnection;
    private final BlockingQueue<ReceivedDatagram> queue;
    private final Thread connectionReceiverThread;
    private final InitialPacket firstInitialPacket;
    private final ByteBuffer data;
    private final PacketMetaData firstInitialPacketMetaData;


    public ServerConnectionThread(ServerConnectionImpl serverConnection, InitialPacket firstInitialPacket, ByteBuffer remainingDatagramData, PacketMetaData initialPacketMetaData) {
        this.serverConnection = serverConnection;
        this.firstInitialPacket = firstInitialPacket;
        this.data = remainingDatagramData;
        this.firstInitialPacketMetaData = initialPacketMetaData;

        queue = new LinkedBlockingQueue<>();
        String threadId = "receiver-" + Bytes.bytesToHex(serverConnection.getOriginalDestinationConnectionId());
        connectionReceiverThread = new Thread(this::process, threadId);
        connectionReceiverThread.start();
    }

    @Override
    public byte[] getOriginalDestinationConnectionId() {
        return serverConnection.getOriginalDestinationConnectionId();
    }

    @Override
    public void parsePackets(int datagramNumber, Instant timeReceived, ByteBuffer data, InetSocketAddress sourceAddress) {
        queue.add(new ReceivedDatagram(datagramNumber, timeReceived, data, sourceAddress));
    }

    @Override
    public boolean isClosed() {
        return serverConnection.isClosed();
    }

    @Override
    public void closeConnection() {
        serverConnection.close();
    }

    @Override
    public void dispose() {
        connectionReceiverThread.interrupt();
    }

    private void process() {
        try {
            if (firstInitialPacket != null) {
                serverConnection.getPacketProcessorChain().processPacket(firstInitialPacket, firstInitialPacketMetaData);
            }

            DatagramParserFilter datagramProcessingChain = new DatagramParserFilter(serverConnection.createParser());

            if (data.hasRemaining()) {
                datagramProcessingChain.processDatagram(data.slice(), firstInitialPacketMetaData);
            }

            while (! connectionReceiverThread.isInterrupted()) {
                ReceivedDatagram datagram = queue.take();
                PacketMetaData metaData = new PacketMetaData(datagram.timeReceived, datagram.sourceAddress, datagram.datagramNumber);
                datagramProcessingChain.processDatagram(datagram.data, metaData);
            }
        }
        catch (InterruptedException e) {
            // Terminate process and thread, see terminate() method
        }
        catch (Throwable error) {
            // Of course, this should never happen. But if it does, there is no point in going on with this connection.
            serverConnection.abortConnection(error);
        }
    }

    @Override
    public String toString() {
        return "ServerConnectionThread[" + Bytes.bytesToHex(getOriginalDestinationConnectionId()) + "]";
    }

    static class ReceivedDatagram {

        final int datagramNumber;
        final Instant timeReceived;
        final ByteBuffer data;
        final InetSocketAddress sourceAddress;

        public ReceivedDatagram(int datagramNumber, Instant timeReceived, ByteBuffer data, InetSocketAddress sourceAddress) {
            this.datagramNumber = datagramNumber;
            this.timeReceived = timeReceived;
            this.data = data;
            this.sourceAddress = sourceAddress;
        }
    }
}
