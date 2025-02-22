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
package tech.kwik.core.server.impl;

import tech.kwik.core.impl.TransportError;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.*;
import tech.kwik.core.util.Bytes;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Consumer;

/**
 * Proxy for server connection that ensures that all processing of received datagrams is executed on a separate thread.
 * This implementation creates a new thread for each connection, so the methods that execute as part of processing
 * received datagrams can use thread-confinement strategy for concurrency control.
 */
public class ServerConnectionThread implements ServerConnectionProxy {

    private final ServerConnectionImpl serverConnection;
    private final BlockingQueue<ReceivedDatagram> queue;
    private final Thread connectionReceiverThread;
    private final List<InitialPacket> firstInitialPackets;
    private final ByteBuffer data;
    private final PacketMetaData firstInitialPacketMetaData;
    private final Logger log;


    public ServerConnectionThread(ServerConnectionImpl serverConnection, List<InitialPacket> firstInitialPackets, ByteBuffer remainingDatagramData, PacketMetaData initialPacketMetaData, Logger log) {
        this.serverConnection = serverConnection;
        this.firstInitialPackets = firstInitialPackets != null? firstInitialPackets: List.of();
        this.data = remainingDatagramData;
        this.firstInitialPacketMetaData = initialPacketMetaData;
        this.log = log;

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
            for (InitialPacket firstInitialPacket : firstInitialPackets) {
                serverConnection.getPacketProcessorChain().processPacket(firstInitialPacket, firstInitialPacketMetaData);
            }

            PacketParser parser = serverConnection.createParser();
            DatagramFilter datagramProcessingChain = wrapWithFilters(parser, serverConnection::increaseAntiAmplificationLimit, serverConnection::datagramProcessed);

            if (data.hasRemaining()) {
                // While processing the first initial packet, the anti amplification limit was already increased with the
                // total datagram size. Now the remainder of the datagram is processed, which will make the
                // AntiAmplificationTrackingFilter to count these bytes again. To compensate for this, the limit is decreased
                serverConnection.increaseAntiAmplificationLimit(-1 * data.remaining());
                datagramProcessingChain.processDatagram(data.slice(), firstInitialPacketMetaData);
            }

            while (! connectionReceiverThread.isInterrupted()) {
                ReceivedDatagram datagram = queue.take();
                PacketMetaData metaData = new PacketMetaData(datagram.timeReceived, datagram.sourceAddress, datagram.datagramNumber, datagram.size);
                datagramProcessingChain.processDatagram(datagram.data, metaData);
            }
        }
        catch (TransportError error) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-11.1
            // "Connection Errors
            //  Errors that result in the connection being unusable, such as an obvious violation of protocol semantics
            //  or corruption of state that affects an entire connection, MUST be signaled using a CONNECTION_CLOSE frame"
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1
            // "Transport Error Codes
            //  This section lists the defined QUIC transport error codes that can be used in a CONNECTION_CLOSE frame
            //  with a type of 0x1c. These errors apply to the entire connection."
            serverConnection.connectionError(error);
        }
        catch (InterruptedException e) {
            // Terminate process and thread, see dispose() method
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

    private DatagramFilter wrapWithFilters(PacketParser parser, Consumer<Integer> receivedPayloadBytesCounterFunction, Runnable postProcessingFunction) {
        return
                // The anti amplification tracking filter is added first, because it must count any packet that makes it to the connection.
                new AntiAmplificationTrackingFilter(receivedPayloadBytesCounterFunction,
                        new ClientAddressFilter(firstInitialPacketMetaData.sourceAddress(), log,
                                new ClientInitialScidFilter(serverConnection.getDestinationConnectionId(), log,
                                        new InitialPacketMinimumSizeFilter(log,
                                                new DatagramPostProcessingFilter(postProcessingFunction, log,
                                                        new DatagramParserFilter(parser))))));
    }

    static class ReceivedDatagram {

        final int datagramNumber;
        final Instant timeReceived;
        final ByteBuffer data;
        final InetSocketAddress sourceAddress;
        final int size;

        public ReceivedDatagram(int datagramNumber, Instant timeReceived, ByteBuffer data, InetSocketAddress sourceAddress) {
            this.datagramNumber = datagramNumber;
            this.timeReceived = timeReceived;
            this.data = data;
            this.sourceAddress = sourceAddress;
            this.size = data.limit();
        }
    }
}
