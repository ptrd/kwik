/*
 * Copyright © 2021, 2022, 2023, 2024 Peter Doornbosch
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

import net.luminis.quic.crypto.Aead;
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.crypto.MissingKeysException;
import net.luminis.quic.impl.DecryptionException;
import net.luminis.quic.impl.InvalidPacketException;
import net.luminis.quic.impl.Role;
import net.luminis.quic.impl.Version;
import net.luminis.quic.impl.VersionHolder;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.NullLogger;
import net.luminis.quic.packet.DatagramFilter;
import net.luminis.quic.packet.DatagramPostProcessingFilter;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.PacketMetaData;
import net.luminis.quic.server.ServerConnectionFactory;
import net.luminis.quic.server.ServerConnectionRegistry;
import net.luminis.quic.util.Bytes;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

/**
 * A server connection candidate: whether an initial packet causes a new server connection to be created will not be
 * decided until the initial packet has been successfully parsed and decrypted (to avoid that corrupt packets change
 * server state).
 *
 * <p>
 * When an initial packet with an unknown destination connection ID arrives, a ServerConnectionCandidate is created,
 * to avoid that ServerConnection objects are create for invalid packets. However, this candidate is registered in the
 * ServerConnectionRegistry, because additional initial packets with the same destination connection ID might arrive, even
 * while still processing the first, and obviously these should not lead to another ServerConnectionCandidate being created,
 * but must be delivered to the same connection (even if still a candidate).
 * Note that this candidate is registered with the original destination connection ID and that only _initial_ packets with
 * this connection ID are allowed, hence the InitialPacketFilterProxy.
 * If additional initial packets with the original destination connection ID arrive, the server candidate will pass
 * them through to the final connection.
 * If the initial packet did not lead to a server connection, the entry with the ODCID will be removed after some time. </o>
 * <p>
 * Now the connection candidate will parse the initial packet, but on a different thread (to limit usage of the thread that
 * is receiving UDP datagrams). If the packet is valid, the candidate creates the final connection and registers this in
 * the ServerConnectionRegistry, but with the new connection ID that is generated by the server connection itself.
 * The server connection is wrapped by a ServerConnectionThread (to ensure that minimal processing is done on the receiver
 * thread and that all processing for a server connection is done on the same thread (to enable thread-confinement strategy))
 * and by a filter chain that does a lot of processing before the packet is delivered to the connection. </p>
 * <p>
 * So, effectively, for each connection the registry will contain:
 * <pre>
 * - ODCID -> InitialPacketFilterProxy -> ServerConnectionCandidate [ -> filter-chain -> adapter -> ServerConnectionThread -> ServerConnectionImpl ]
 * -   CID -> ServerConnectionWrapper -> filter-chain -> adapter -> ServerConnectionThread -> ServerConnectionImpl
 *                                     \- - - - - - - - - - - - -/
 * </pre>
 * When new connection IDs are sent to the peer, additional entries will be added to the registry to ensure these new
 * connection IDs also map to the same connection. </p>
 */
public class ServerConnectionCandidate implements ServerConnectionProxy, DatagramFilter {

    private final Version quicVersion;
    private final InetSocketAddress clientAddress;
    private final byte[] dcid;
    private final ServerConnectionFactory serverConnectionFactory;
    private final ServerConnectionRegistry connectionRegistry;
    private final Logger log;
    private final DatagramFilter filterChain;
    private final ReentrantLock registrationLock;
    private volatile ServerConnectionProxy registeredConnection;
    private final ExecutorService executor;
    private final ScheduledExecutorService scheduledExecutor;
    private volatile boolean closed;


    public ServerConnectionCandidate(Context context, Version version, InetSocketAddress clientAddress, byte[] scid, byte[] dcid,
                                     ServerConnectionFactory serverConnectionFactory, ServerConnectionRegistry connectionRegistry, Logger log) {
        this.executor = context.getSharedServerExecutor();
        this.scheduledExecutor = context.getSharedScheduledExecutor();
        this.quicVersion = version;
        this.clientAddress = clientAddress;
        this.dcid = dcid;
        this.serverConnectionFactory = serverConnectionFactory;
        this.connectionRegistry = connectionRegistry;
        this.log = log;

        filterChain = new InitialPacketMinimumSizeFilter(log, this);
        registrationLock = new ReentrantLock();
    }

    @Override
    public byte[] getOriginalDestinationConnectionId() {
        return dcid;
    }

    @Override
    public void parsePackets(int datagramNumber, Instant timeReceived, ByteBuffer data, InetSocketAddress sourceAddress) {
        // Execute packet parsing on separate thread, to make this method return a.s.a.p.
        executor.submit(() -> {
            // Serialize processing (per connection candidate): duplicate initial packets might arrive faster than they are processed.
            synchronized (this) {
                // Because of possible queueing in the executor, a connection might already exist (i.e. when multiple
                // packets queued before the connection was registered).
                if (registeredConnection != null) {
                    registeredConnection.parsePackets(datagramNumber, timeReceived, data, sourceAddress);
                    return;
                }

                PacketMetaData metaData = new PacketMetaData(timeReceived, sourceAddress, datagramNumber);
                filterChain.processDatagram(data, metaData);
            }
        });
    }

    @Override
    public void processDatagram(ByteBuffer data, PacketMetaData metaData) {
        try {
            int datagramNumber = metaData.datagramNumber();
            Instant timeReceived = metaData.timeReceived();
            InitialPacket initialPacket = parseInitialPacket(datagramNumber, timeReceived, data);

            log.received(timeReceived, datagramNumber, initialPacket);
            log.debug("Parsed packet with size " + data.position() + "; " + data.remaining() + " bytes left.");

            // Packet is valid. This is the moment to create a real server connection and continue processing.
            if (registeredConnection == null) {
                createAndRegisterServerConnection(initialPacket, metaData, data);
            }
        }
        catch (InvalidPacketException | DecryptionException cannotParsePacket) {
            // Drop packet without any action (i.e. do not send anything; do not change state; avoid unnecessary processing)
            log.debug("Dropped invalid initial packet (no connection created)");
            // But still the (now useless) candidate should be removed from the connection registry.
            // To avoid race conditions with incoming duplicated first packets (possibly leading to scheduling
            // a task for this candidate while it is not registered anymore), the removal of the candidate is
            // delayed until connection setup is over.
            // The delay should be longer then the maximum connection timeout clients (are likely to) use.
            // It can be fairly large because the removal is only needed to avoid unused connection candidates pile up.
            scheduledExecutor.schedule(() -> {
                        // But only if no connection is created in the meantime (which will do the cleanup)
                        if (registeredConnection == null) {
                            connectionRegistry.deregisterConnection(this, dcid);
                        }
                    },
                    30, TimeUnit.SECONDS);
        } catch (Exception error) {
            log.error("error while parsing or processing initial packet", error);
        }
    }

    private void createAndRegisterServerConnection(InitialPacket initialPacket, PacketMetaData metaData, ByteBuffer datagramData) {
        Version quicVersion = initialPacket.getVersion();
        byte[] originalDcid = initialPacket.getDestinationConnectionId();

        registrationLock.lock();
        try {
            if (!closed) {
                ServerConnectionImpl connection = serverConnectionFactory.createNewConnection(quicVersion, clientAddress, initialPacket.getSourceConnectionId(), originalDcid);

                // Pass the initial packet for processing, so it is processed on the server thread (enabling thread confinement concurrency strategy)
                ServerConnectionProxy connectionProxy = serverConnectionFactory.createServerConnectionProxy(connection, initialPacket, datagramData, metaData);
                int datagramSize = datagramData.limit();
                connection.increaseAntiAmplificationLimit(datagramSize);

                ServerConnectionProxy wrappedConnection = wrapWithFilters(connectionProxy, connection::increaseAntiAmplificationLimit, connection::datagramProcessed);

                // Register new connection with the new connection id (the one generated by the server)
                connectionRegistry.registerConnection(wrappedConnection, connection.getInitialConnectionId());
                registeredConnection = wrappedConnection;
            }
        }
        finally {
            registrationLock.unlock();
        }
    }

    private ServerConnectionProxy wrapWithFilters(ServerConnectionProxy connection, Consumer<Integer> receivedPayloadBytesCounterFunction, Runnable postProcessingFunction) {
        DatagramFilter adapter = (data, metaData) -> connection.parsePackets(metaData.datagramNumber(), metaData.timeReceived(), data, metaData.sourceAddress());

        // The wrapper takes care of propagating other (non-filter) methods to the connection proxy.
        return new ServerConnectionWrapper(connection, log,
                        // The anti amplification tracking filter is added first, because it must count any packet that makes it to the connection.
                        new AntiAmplificationTrackingFilter(receivedPayloadBytesCounterFunction,
                                new ClientAddressFilter(clientAddress, log,
                                        new InitialPacketMinimumSizeFilter(log,
                                                new DatagramPostProcessingFilter(postProcessingFunction, log,
                                                        adapter)))));
    }

    @Override
    public boolean isClosed() {
        return false;
    }

    @Override
    public void closeConnection() {
        registrationLock.lock();
        try {
            if (registeredConnection != null) {
                registeredConnection.closeConnection();
            }
            closed = true;
        }
        finally {
            registrationLock.unlock();
        }
    }

    @Override
    public void dispose() {
    }

    InitialPacket parseInitialPacket(int datagramNumber, Instant timeReceived, ByteBuffer data) throws InvalidPacketException, DecryptionException {
        // Note that the caller already has extracted connection id's from the raw data, so checking for minimal length is not necessary here.
        int flags = data.get();
        data.rewind();

        if ((flags & 0x40) != 0x40) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-17.2
            // "Fixed Bit:  The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotiation packet.
            //  Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded."
            throw new InvalidPacketException();
        }

        // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-17.2
        // "The most significant bit (0x80) of byte 0 (the first byte) is set to 1 for long headers."
        // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-17.2.2
        // "An Initial packet uses long headers with a type value of 0x0."
        if (InitialPacket.isInitialType((flags & 0x30) >> 4, quicVersion)) {
            InitialPacket packet = new InitialPacket(quicVersion);
            ConnectionSecrets connectionSecrets = new ConnectionSecrets(new VersionHolder(quicVersion), Role.Server, null, new NullLogger());
            byte[] originalDcid = dcid;
            connectionSecrets.computeInitialKeys(originalDcid);
            try {
                Aead aead = connectionSecrets.getPeerAead(packet.getEncryptionLevel());
                packet.parse(data, aead, 0, new NullLogger(), 0);
                return packet;
            } catch (MissingKeysException e) {
                // Impossible, as initial keys have just been computed.
                throw new RuntimeException(e);
            }
        }
        throw new InvalidPacketException();
    }

    @Override
    public String toString() {
        return "ServerConnectionCandidate[" + Bytes.bytesToHex(dcid) + "]";
    }
}
