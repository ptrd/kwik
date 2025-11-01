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
package tech.kwik.core.server.impl;

import tech.kwik.agent15.engine.TlsServerEngineFactory;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicConstants;
import tech.kwik.core.concurrent.DaemonThreadFactory;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.crypto.MissingKeysException;
import tech.kwik.core.frame.ConnectionCloseFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.InitialPacket;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.packet.VersionNegotiationPacket;
import tech.kwik.core.receive.RawPacket;
import tech.kwik.core.receive.Receiver;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnectionFactory;
import tech.kwik.core.server.ServerConnector;
import tech.kwik.core.util.Bytes;
import tech.kwik.core.util.MemoryWatcher;

import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import static tech.kwik.core.common.EncryptionLevel.Initial;

/**
 * Listens for QUIC connections on a given port. Requires server certificate and corresponding private key.
 */
public class ServerConnectorImpl implements ServerConnector {

    public static int DEFAULT_CLOSE_TIMEOUT_IN_SECONDS = 30;

    private final Receiver receiver;
    private final Logger log;
    private final List<QuicConnection.QuicVersion> supportedVersions;
    private final List<Integer> supportedVersionIds;
    private final DatagramSocket serverSocket;
    private TlsServerEngineFactory tlsEngineFactory;
    private final ServerConnectionFactory serverConnectionFactory;
    private ApplicationProtocolRegistry applicationProtocolRegistry;
    private final ExecutorService sharedExecutor;
    private final ScheduledExecutorService sharedScheduledExecutor;
    private final Context context;
    private final ServerConnectionRegistryImpl connectionRegistry;
    private final int connectionIdLength;
    private volatile boolean acceptingNewConnections;
    private final Thread serverReceiveLoop;
    private volatile boolean closing;

    /**
     * @deprecated use {@link ServerConnector.Builder} instead
     * @param port
     * @param certificateFile
     * @param certificateKeyFile
     * @param supportedVersions
     * @param requireRetry
     * @param log
     * @throws Exception
     */
    @Deprecated
    public ServerConnectorImpl(int port, InputStream certificateFile, InputStream certificateKeyFile, List<QuicConnection.QuicVersion> supportedVersions, boolean requireRetry, Logger log) throws Exception {
        this(new DatagramSocket(port), certificateFile, certificateKeyFile, supportedVersions, requireRetry, log);
    }

    /**
     * @deprecated use {@link ServerConnector.Builder} instead
     * @param socket
     * @param certificateFile
     * @param certificateKeyFile
     * @param supportedVersions
     * @param requireRetry
     * @param log
     * @throws Exception
     */
    @Deprecated
    public ServerConnectorImpl(DatagramSocket socket, InputStream certificateFile, InputStream certificateKeyFile, List<QuicConnection.QuicVersion> supportedVersions, boolean requireRetry, Logger log) throws Exception {
        this(socket, certificateFile, certificateKeyFile, supportedVersions, getDefaultConfiguration(requireRetry), log);
    }

    private ServerConnectorImpl(DatagramSocket socket, InputStream certificateFile, InputStream certificateKeyFile, List<QuicConnection.QuicVersion> supportedVersions, ServerConnectionConfig configuration, Logger log) throws Exception {
        this(socket, new TlsServerEngineFactory(certificateFile, certificateKeyFile), supportedVersions, configuration, log);
    }

    private ServerConnectorImpl(DatagramSocket socket, KeyStore keyStore, String alias, char[] keyPassword, String ecCurve, List<QuicConnection.QuicVersion> supportedVersions, ServerConnectionConfig configuration, Logger log) throws Exception {
        this(socket, new TlsServerEngineFactory(keyStore, alias, keyPassword, ecCurve), supportedVersions, configuration, log);
    }

    private ServerConnectorImpl(DatagramSocket socket, TlsServerEngineFactory tlsEngineFactory, List<QuicConnection.QuicVersion> supportedVersions, ServerConnectionConfig configuration, Logger log) {
        this.serverSocket = socket;
        this.tlsEngineFactory = tlsEngineFactory;
        this.supportedVersions = supportedVersions;
        this.log = Objects.requireNonNull(log);
        connectionIdLength = configuration.connectionIdLength();

        applicationProtocolRegistry = new ApplicationProtocolRegistry();
        connectionRegistry = new ServerConnectionRegistryImpl(log);
        serverConnectionFactory = new ServerConnectionFactory(serverSocket, tlsEngineFactory,
                configuration, applicationProtocolRegistry, connectionRegistry, this::closed, log);

        supportedVersionIds = supportedVersions.stream()
                .map(Version::of)
                .map(Version::getId)
                .collect(Collectors.toList());
        receiver = new Receiver(serverSocket, log, exception -> System.exit(9));

        int maxSharedExecutorThreads = 10;
        sharedExecutor = new ThreadPoolExecutor(1, maxSharedExecutorThreads, 60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<Runnable>(), new DaemonThreadFactory("server connector shared executor"));
        sharedScheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        context = new ServerConnectorContext();

        serverReceiveLoop = new Thread(this::receiveLoop, "server receive loop");

        new MemoryWatcher(85, log);
    }

    // Intentionally private: for use with deprecated constructors only.
    private static ServerConnectionConfig getDefaultConfiguration(boolean requireRetry) {
        return ServerConnectionConfig.builder()
                .maxIdleTimeoutInSeconds(30)
                .maxUnidirectionalStreamBufferSize(1_000_000)
                .maxBidirectionalStreamBufferSize(1_000_000)
                .maxConnectionBufferSize(10_000_000)
                .maxOpenPeerInitiatedUnidirectionalStreams(10)
                .maxOpenPeerInitiatedBidirectionalStreams(100)
                .retryRequired(requireRetry)
                .connectionIdLength(8)
                .build();
    }

    public void registerApplicationProtocol(String protocol, ApplicationProtocolConnectionFactory protocolConnectionFactory) {
        applicationProtocolRegistry.registerApplicationProtocol(protocol, protocolConnectionFactory);
    }

    public Set<String> getRegisteredApplicationProtocols() {
        return applicationProtocolRegistry.getRegisteredApplicationProtocols();
    }

    public void start() {
        acceptingNewConnections = true;
        receiver.start();

        serverReceiveLoop.start();
        log.info("Kwik server connector started on port " + serverSocket.getLocalPort() + "; supported application protocols: "
                + applicationProtocolRegistry.getRegisteredApplicationProtocols());
    }

    public void stopAcceptingNewConnections() {
        acceptingNewConnections = false;
    }

    protected void receiveLoop() {
        while (true) {
            try {
                RawPacket rawPacket = receiver.get((int) Duration.ofDays(10 * 365).toSeconds());
                process(rawPacket);
            }
            catch (InterruptedException e) {
                if (! closing) {
                    log.error("receiver loop interrupted and terminated");
                }
                break;
            }
            catch (Exception runtimeError) {
                log.error("Uncaught exception in server receive loop", runtimeError);
            }
        }
    }

    protected void process(RawPacket rawPacket) {
        ByteBuffer data = rawPacket.getData();
        if (isValidLongHeaderPacket(data)) {
            processLongHeaderPacket(new InetSocketAddress(rawPacket.getAddress(), rawPacket.getPort()), data);
        }
        else if (isValidShortHeaderPacket(data)) {
            processShortHeaderPacket(new InetSocketAddress(rawPacket.getAddress(), rawPacket.getPort()), data);
        }
        else {
            // There is another reason why a long header packet could be invalid (inconsistent connection ID lengths),
            // but specification is only explicit about the incorrect fixed bit:
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
            // "Fixed Bit: The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotiation packet.
            //  Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded."
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1
            // "Fixed Bit: The next bit (0x40) of byte 0 is set to 1. Packets containing a zero value for this bit are
            //  not valid packets in this version and MUST be discarded. "
            log.warn(String.format("Invalid Quic packet (flags: %02x) is discarded", (int) data.get()));
        }
    }

    /**
     * Returns whether the given data represents a valid long header packet, independent of the QUIC version (RFC 8999).
     * See https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1
     * @param data
     * @return
     */
    protected static boolean isValidLongHeaderPacket(ByteBuffer data) {
        // https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1
        // "Long Header Packet {
        //    Header Form (1) = 1,
        //    Version-Specific Bits (7),
        //    Version (32),
        //    Destination Connection ID Length (8),
        //    Destination Connection ID (0..2040),
        //    Source Connection ID Length (8),
        //    Source Connection ID (0..2040),
        //    Version-Specific Data (..),"
        // }"
        // So: flags (1) + version (4) + dcid length (1) + dcid + scid length (1) + scid
        if (data.remaining() > 1 + 4 + 1 + 1) {
            int flags = data.get(0);
            if ((flags & 0x80) == 0x80) {
                int dcidLength = data.get(5) & 0xff;
                if (data.remaining() > 5 + 1 + dcidLength) {
                    int scidLength = data.get(5 + 1 + dcidLength) & 0xff;
                    if (data.remaining() > 5 + 1 + dcidLength + 1 + scidLength) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Returns whether the given data represents a valid short header packet
     * given the connection ID length used by this server and the QUIC versions supported by this server.
     *
     * @param data
     * @return
     */
    protected boolean isValidShortHeaderPacket(ByteBuffer data) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1
        // "1-RTT Packet {
        //    Header Form (1) = 0,
        //    Fixed Bit (1) = 1,
        //    Spin Bit (1),
        //    Reserved Bits (2),
        //    Key Phase (1),
        //    Packet Number Length (2),
        //    Destination Connection ID (0..160),
        //    Packet Number (8..32),
        //    Packet Payload (8..),
        //  }"
        if (data.remaining() > 1 + connectionIdLength + 1 + 1) {
            int flags = data.get(0);
            if ((flags & 0xc0) == 0x40) {
                return true;
            }
        }
        return false;
    }

    private void processLongHeaderPacket(InetSocketAddress clientAddress, ByteBuffer data) {
        assert isValidLongHeaderPacket(data);

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
        // "Long Header Packet {
        //    (...)
        //    Version (32),
        //    Destination Connection ID Length (8),
        //    Destination Connection ID (0..160),
        //    Source Connection ID Length (8),
        //    Source Connection ID (0..160),
        //    Type-Specific Payload (..),
        //  }"
        data.mark();
        int flags = data.get();
        int version = data.getInt();
        int dcidLength = data.get() & 0xff;

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
        // "The byte following the version contains the length in bytes of the Destination Connection ID field that
        //  follows it. This length is encoded as an 8-bit unsigned integer. In QUIC version 1, this value MUST NOT
        //  exceed 20. Endpoints that receive a version 1 long header with a value larger than 20 MUST drop the packet.
        //  In order to properly form a Version Negotiation packet, servers SHOULD be able to read longer connection IDs
        //  from other QUIC versions."
        if (dcidLength > 20) {
            if (version == Version.QUIC_version_1.getId() || version == Version.QUIC_version_2.getId()) {
                // "MUST drop the packet"
                return;
            }
        }

        byte[] dcid = new byte[dcidLength];
        data.get(dcid);
        int scidLength = data.get() & 0xff;
        byte[] scid = new byte[scidLength];
        data.get(scid);
        data.reset();

        if (supportedVersionIds.contains(version)) {
            if (InitialPacket.isInitial(flags, version)) {
                processInitial(clientAddress, data, version, dcid, scid);
            }
            else {
                connectionRegistry.isExistingConnection(clientAddress, dcid).ifPresentOrElse(
                        c -> c.parsePackets(0, Instant.now(), data, clientAddress),
                        () -> log.warn("Discarding packet for non-existent connection " + Bytes.bytesToHex(dcid)));
            }
        }
        else {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-5.2.2
            // "If a server receives a packet that indicates an unsupported version and if the packet is large enough to
            //  initiate a new connection for any supported version, the server SHOULD send a Version Negotiation packet"
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1
            // "A server MUST discard an Initial packet that is carried in a UDP datagram with a payload that is smaller
            //  than the smallest allowed maximum datagram size of 1200 bytes. "
            if (data.limit() >= 1200) {
                log.received(Instant.now(), 0, null, dcid, scid);
                sendVersionNegotiationPacket(clientAddress, data, dcidLength);
            }
        }
    }

    private void processInitial(InetSocketAddress clientAddress, ByteBuffer data, int version, byte[] dcid, byte[] scid) {
        if (acceptingNewConnections) {
            ServerConnectionProxy connection;
            // Check-and-create often requires a lock to avoid race conditions, but in this case this is not necessary
            // because this method is only called from one thread (see receiveLoop)
            connection = connectionRegistry.isExistingConnection(clientAddress, dcid)
                    .orElseGet(() -> createNewConnection(version, clientAddress, scid, dcid));
            connection.parsePackets(0, Instant.now(), data, clientAddress);
        }
        else {
            log.warn("Server not accepting new connections");
            sendConnectionRefused(version, dcid, scid, clientAddress);
        }
    }

    private void sendConnectionRefused(int rawVersion, byte[] dcid, byte[] scid, InetSocketAddress clientAddress) {
        Version version = Version.parse(rawVersion);
        QuicFrame connectionClosed = new ConnectionCloseFrame(version, QuicConstants.TransportErrorCode.CONNECTION_REFUSED.value, "");
        InitialPacket connectionRefusedResponse = new InitialPacket(version, dcid, scid, null, connectionClosed);
        connectionRefusedResponse.setPacketNumber(0);

        ConnectionSecrets connectionSecrets = new ConnectionSecrets(VersionHolder.with(version), Role.Server, null, log);
        connectionSecrets.computeInitialKeys(dcid);
        try {
            sendPacket(clientAddress, connectionRefusedResponse, connectionSecrets.getOwnAead(Initial));
        }
        catch (MissingKeysException e) {
            // Impossible, as we just computed the keys
        }
    }

    private void processShortHeaderPacket(InetSocketAddress clientAddress, ByteBuffer data) {
        byte[] dcid = new byte[connectionIdLength];
        data.position(1);
        data.get(dcid);
        data.rewind();
        Optional<ServerConnectionProxy> connection = connectionRegistry.isExistingConnection(clientAddress, dcid);
        connection.ifPresentOrElse(c -> c.parsePackets(0, Instant.now(), data, clientAddress),
                () -> log.warn("Discarding short header packet addressing non existent connection " + Bytes.bytesToHex(dcid)));
    }

    private ServerConnectionProxy createNewConnection(int versionValue, InetSocketAddress clientAddress, byte[] scid, byte[] originalDcid) {
        Version version = Version.parse(versionValue);
        ServerConnectionProxy connectionCandidate = new ServerConnectionCandidate(context, version, clientAddress, scid, originalDcid,
                serverConnectionFactory, connectionRegistry, log);
        // Register new connection now with the original connection id, as retransmitted initial packets with the
        // same original dcid might be received (for example when the server response does not reach the client).
        // Such packets must _not_ lead to new connection candidate. Moreover, if it is an initial packet, it must be
        // passed to the connection, because (if valid) it will change the anti-amplification limit.
        connectionRegistry.registerConnection(new InitialPacketFilterProxy(connectionCandidate, version, log), originalDcid);

        return connectionCandidate;
    }

    private void sendVersionNegotiationPacket(InetSocketAddress clientAddress, ByteBuffer data, int dcidLength) {
        data.rewind();
        if (data.remaining() >= 1 + 4 + 1 + dcidLength + 1) {
            byte[] dcid = new byte[dcidLength];
            data.position(1 + 4 + 1);
            data.get(dcid);
            int scidLength = data.get() & 0xff;
            byte[] scid = new byte[scidLength];
            if (scidLength > 0) {
                data.get(scid);
            }
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2.1
            // "The server MUST include the value from the Source Connection ID field of the packet it receives in the
            //  Destination Connection ID field. The value for Source Connection ID MUST be copied from the Destination
            //  Connection ID of the received packet, ..."
            List<Version> versions = supportedVersions.stream().map(Version::of).collect(Collectors.toList());
            VersionNegotiationPacket versionNegotiationPacket = new VersionNegotiationPacket(versions, dcid, scid);
            sendPacket(clientAddress, versionNegotiationPacket, null);
        }
    }

    /**
     * Send packet to client when the intent is not to establish a new connection.
     * @param clientAddress
     * @param packet
     * @param aead
     */
    private void sendPacket(InetSocketAddress clientAddress, QuicPacket packet, Aead aead) {
        byte[] packetBytes = packet.generatePacketBytes(aead);
        DatagramPacket datagram = new DatagramPacket(packetBytes, packetBytes.length, clientAddress.getAddress(), clientAddress.getPort());
        try {
            serverSocket.send(datagram);
            log.sent(Instant.now(), packet);
        }
        catch (IOException e) {
            log.error("Sending " + packet + " failed", e);
        }
    }

    private void closed(ServerConnectionImpl connection) {
        ServerConnectionProxy removedConnection = connectionRegistry.removeConnection(connection);
        removedConnection.dispose();
    }

    protected void closeAllConnections() {
        connectionRegistry.getAllConnections().forEach(ServerConnectionProxy::closeConnection);
    }

    @Override
    public void close() {
        close(Duration.ofSeconds(DEFAULT_CLOSE_TIMEOUT_IN_SECONDS));
    }

    protected void close(Duration timeout) {
        log.info("Shutting down " + this);
        closing = true;
        stopAcceptingNewConnections();
        closeAllConnections();
        connectionRegistry.waitForAllConnectionsToClose(timeout);

        serverReceiveLoop.interrupt();
        receiver.shutdown();
        serverSocket.close();
        tlsEngineFactory.dispose();
        sharedExecutor.shutdown();
        sharedScheduledExecutor.shutdown();
    }


    @Override
    public String toString() {
        return "ServerConnector[" + serverSocket.getLocalPort() + ":" + applicationProtocolRegistry.getRegisteredApplicationProtocols() + "]";
    }

    private class ServerConnectorContext implements Context {

        @Override
        public ExecutorService getSharedServerExecutor() {
            return sharedExecutor;
        }

        @Override
        public ScheduledExecutorService getSharedScheduledExecutor() {
            return sharedScheduledExecutor;
        }
    }

    public static class BuilderImpl implements Builder {

        private int port;
        private DatagramSocket socket;
        private InputStream certificateFile;
        private InputStream certificateKeyFile;
        private List<QuicConnection.QuicVersion> supportedVersions = new ArrayList<>(List.of(QuicConnection.QuicVersion.V1));
        private ServerConnectionConfig configuration = getDefaultConfiguration(true);
        private Logger log;
        private KeyStore keyStore;
        private String certificateAlias;
        private char[] privateKeyPassword;
        private String ecCurve;

        @Override
        public ServerConnector.Builder withPort(int port) {
            this.port = port;
            return this;
        }

        @Override
        public ServerConnector.Builder withSocket(DatagramSocket socket) {
            this.socket = socket;
            return this;
        }

        /**
         * @deprecated Use withKeyStore instead, which provides support for a broader range of certificate types
         * @param certificateFile
         * @param certificateKeyFile
         * @return
         */
        @Deprecated
        @Override
        public ServerConnector.Builder withCertificate(InputStream certificateFile, InputStream certificateKeyFile) {
            this.certificateFile = Objects.requireNonNull(certificateFile);
            this.certificateKeyFile = Objects.requireNonNull(certificateKeyFile);
            return this;
        }

        @Override
        public ServerConnector.Builder withKeyStore(KeyStore keyStore, String certificateAlias, char[] privateKeyPassword) {
            this.keyStore = Objects.requireNonNull(keyStore);
            this.certificateAlias = Objects.requireNonNull(certificateAlias);
            this.privateKeyPassword = Objects.requireNonNull(privateKeyPassword);
            return this;
        }

        @Override
        public ServerConnector.Builder withKeyStore(KeyStore keyStore, String certificateAlias, char[] privateKeyPassword, String ecCurve) {
            this.keyStore = Objects.requireNonNull(keyStore);
            this.certificateAlias = Objects.requireNonNull(certificateAlias);
            this.privateKeyPassword = Objects.requireNonNull(privateKeyPassword);
            if (ecCurve != null && !List.of("secp256r1", "secp384r1", "secp521r1").contains(ecCurve)) {
                throw new IllegalArgumentException("Invalid EC curve: " + ecCurve);
            }
            this.ecCurve = ecCurve;
            return this;
        }

        @Override
        public ServerConnector.Builder withSupportedVersions(List<QuicConnection.QuicVersion> supportedVersions) {
            this.supportedVersions.addAll(supportedVersions);
            return this;
        }

        @Override
        public ServerConnector.Builder withSupportedVersion(QuicConnection.QuicVersion supportedVersion) {
            this.supportedVersions.add(supportedVersion);
            return this;
        }

        @Override
        public ServerConnector.Builder withConfiguration(ServerConnectionConfig configuration) {
            this.configuration = Objects.requireNonNull(configuration);
            return this;
        }

        @Override
        public ServerConnector.Builder withLogger(Logger log) {
            this.log = log;
            return this;
        }

        @Override
        public ServerConnector build() throws SocketException, CertificateException {
            if (socket == null && port == 0) {
                throw new IllegalStateException("port number not set");
            }
            if (certificateFile == null && keyStore == null) {
                throw new IllegalStateException("server certificate not set");
            }

            if (socket == null) {
                socket = new DatagramSocket(port);
            }

            try {
                TlsServerEngineFactory tlsEngineFactory;
                if (keyStore != null) {
                    tlsEngineFactory = new TlsServerEngineFactory(keyStore, certificateAlias, privateKeyPassword, ecCurve);
                }
                else {
                    tlsEngineFactory = new TlsServerEngineFactory(certificateFile, certificateKeyFile);
                }
                return new ServerConnectorImpl(socket, tlsEngineFactory, supportedVersions, configuration, log);
            }
            catch (IOException e) {
                // Impossible, exception is never thrown by TlsServerEngineFactory constructor.
                throw new RuntimeException(e);
            }
            catch (InvalidKeySpecException e) {
                // Impossible, exception is never thrown by TlsServerEngineFactory constructor.
                throw new RuntimeException(e);
            }
        }
    }
}
