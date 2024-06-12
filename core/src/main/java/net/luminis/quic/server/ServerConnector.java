/*
 * Copyright © 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.server;

import net.luminis.quic.core.EncryptionLevel;
import net.luminis.quic.impl.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.VersionNegotiationPacket;
import net.luminis.quic.receive.RawPacket;
import net.luminis.quic.receive.Receiver;
import net.luminis.tls.handshake.TlsServerEngineFactory;
import net.luminis.tls.util.ByteUtils;

import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.stream.Collectors;

/**
 * Listens for QUIC connections on a given port. Requires server certificate and corresponding private key.
 */
public class ServerConnector {

    private static final int MINIMUM_LONG_HEADER_LENGTH = 1 + 4 + 1 + 0 + 1 + 0;

    private final Receiver receiver;
    private final Logger log;
    private final List<Version> supportedVersions;
    private final List<Integer> supportedVersionIds;
    private final DatagramSocket serverSocket;
    private TlsServerEngineFactory tlsEngineFactory;
    private final ServerConnectionFactory serverConnectionFactory;
    private ApplicationProtocolRegistry applicationProtocolRegistry;
    private final ExecutorService sharedExecutor = Executors.newSingleThreadExecutor();
    private final ScheduledExecutorService sharedScheduledExecutor = Executors.newSingleThreadScheduledExecutor();
    private Context context;
    private ServerConnectionRegistryImpl connectionRegistry;
    private int connectionIdLength;

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
    public ServerConnector(int port, InputStream certificateFile, InputStream certificateKeyFile, List<Version> supportedVersions, boolean requireRetry, Logger log) throws Exception {
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
    public ServerConnector(DatagramSocket socket, InputStream certificateFile, InputStream certificateKeyFile, List<Version> supportedVersions, boolean requireRetry, Logger log) throws Exception {
        this(socket, certificateFile, certificateKeyFile, supportedVersions, getDefaultConfiguration(requireRetry), log);
    }

    private ServerConnector(DatagramSocket socket, InputStream certificateFile, InputStream certificateKeyFile, List<Version> supportedVersions, ServerConnectionConfig configuration, Logger log) throws Exception {
        this(socket, new TlsServerEngineFactory(certificateFile, certificateKeyFile), supportedVersions, configuration, log);
    }

    private ServerConnector(DatagramSocket socket, KeyStore keyStore, String alias, char[] keyPassword, List<Version> supportedVersions, ServerConnectionConfig configuration, Logger log) throws Exception {
        this(socket, new TlsServerEngineFactory(keyStore, alias, keyPassword), supportedVersions, configuration, log);
    }

    private ServerConnector(DatagramSocket socket, TlsServerEngineFactory tlsEngineFactory, List<Version> supportedVersions, ServerConnectionConfig configuration, Logger log) throws Exception {
        this.serverSocket = socket;
        this.tlsEngineFactory = tlsEngineFactory;
        this.supportedVersions = supportedVersions;
        this.log = Objects.requireNonNull(log);
        connectionIdLength = configuration.connectionIdLength();

        applicationProtocolRegistry = new ApplicationProtocolRegistry();
        connectionRegistry = new ServerConnectionRegistryImpl(log);
        serverConnectionFactory = new ServerConnectionFactory(serverSocket, tlsEngineFactory,
                configuration, applicationProtocolRegistry, connectionRegistry, this::closed, log);

        supportedVersionIds = supportedVersions.stream().map(version -> version.getId()).collect(Collectors.toList());
        receiver = new Receiver(serverSocket, log, exception -> System.exit(9));
        context = new ServerConnectorContext();
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
        receiver.start();

        new Thread(this::receiveLoop, "server receive loop").start();
        log.info("Kwik server connector started on port " + serverSocket.getLocalPort()+ "; supported application protocols: "
                + applicationProtocolRegistry.getRegisteredApplicationProtocols());
    }

    protected void receiveLoop() {
        while (true) {
            try {
                RawPacket rawPacket = receiver.get((int) Duration.ofDays(10 * 365).toSeconds());
                process(rawPacket);
            }
            catch (InterruptedException e) {
                log.error("receiver interrupted (ignoring)");
                break;
            }
            catch (Exception runtimeError) {
                log.error("Uncaught exception in server receive loop", runtimeError);
            }
        }
    }

    protected void process(RawPacket rawPacket) {
        ByteBuffer data = rawPacket.getData();
        int flags = data.get();
        data.rewind();
        if ((flags & 0b1100_0000) == 0b1100_0000) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2
            // "Header Form:  The most significant bit (0x80) of byte 0 (the first byte) is set to 1 for long headers."
            processLongHeaderPacket(new InetSocketAddress(rawPacket.getAddress(), rawPacket.getPort()), data);
        } else if ((flags & 0b1100_0000) == 0b0100_0000) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.3
            // "Header Form:  The most significant bit (0x80) of byte 0 is set to 0 for the short header.
            processShortHeaderPacket(new InetSocketAddress(rawPacket.getAddress(), rawPacket.getPort()), data);
        } else {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.3
            // "The next bit (0x40) of byte 0 is set to 1. Packets containing a zero value for this bit are not valid
            //  packets in this version and MUST be discarded."
            log.warn(String.format("Invalid Quic packet (flags: %02x) is discarded", flags));
        }
    }

    private void processLongHeaderPacket(InetSocketAddress clientAddress, ByteBuffer data) {
        if (data.remaining() >= MINIMUM_LONG_HEADER_LENGTH) {
            data.position(1);
            int version = data.getInt();

            data.position(5);
            int dcidLength = data.get() & 0xff;
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2
            // "In QUIC version 1, this value MUST NOT exceed 20. Endpoints that receive a version 1 long header with a
            //  value larger than 20 MUST drop the packet. In order to properly form a Version Negotiation packet,
            //  servers SHOULD be able to read longer connection IDs from other QUIC versions."
            if (dcidLength > 20) {
                if (initialWithUnspportedVersion(data, version)) {
                    // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-6
                    // "A server sends a Version Negotiation packet in response to each packet that might initiate a new connection;"
                    sendVersionNegotiationPacket(clientAddress, data, dcidLength);
                }
                return;
            }
            if (data.remaining() >= dcidLength + 1) {  // after dcid at least one byte scid length
                byte[] dcid = new byte[dcidLength];
                data.get(dcid);
                int scidLength = data.get() & 0xff;
                if (data.remaining() >= scidLength) {
                    byte[] scid = new byte[scidLength];
                    data.get(scid);
                    data.rewind();

                    Optional<ServerConnectionProxy> connection = connectionRegistry.isExistingConnection(clientAddress, dcid);
                    if (connection.isEmpty()) {
                        synchronized (this) {
                            if (mightStartNewConnection(data, version, dcid) && connectionRegistry.isExistingConnection(clientAddress, dcid).isEmpty()) {
                                connection = Optional.of(createNewConnection(version, clientAddress, scid, dcid));
                            } else if (initialWithUnspportedVersion(data, version)) {
                                log.received(Instant.now(), 0, EncryptionLevel.Initial, dcid, scid);
                                // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-6
                                // "A server sends a Version Negotiation packet in response to each packet that might initiate a new connection;"
                                sendVersionNegotiationPacket(clientAddress, data, dcidLength);
                            }
                        }
                    }
                    connection.ifPresent(c -> c.parsePackets(0, Instant.now(), data, clientAddress));
                }
            }
        }
    }

    private void processShortHeaderPacket(InetSocketAddress clientAddress, ByteBuffer data) {
        byte[] dcid = new byte[connectionIdLength];
        data.position(1);
        data.get(dcid);
        data.rewind();
        Optional<ServerConnectionProxy> connection = connectionRegistry.isExistingConnection(clientAddress, dcid);
        connection.ifPresentOrElse(c -> c.parsePackets(0, Instant.now(), data, clientAddress),
                () -> log.warn("Discarding short header packet addressing non existent connection " + ByteUtils.bytesToHex(dcid)));
    }

    private boolean mightStartNewConnection(ByteBuffer packetBytes, int version, byte[] dcid) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-7.2
        // "This Destination Connection ID MUST be at least 8 bytes in length."
        if (dcid.length >= 8) {
            return supportedVersionIds.contains(version);
        } else {
            return false;
        }
    }

    private boolean initialWithUnspportedVersion(ByteBuffer packetBytes, int version) {
        packetBytes.rewind();
        int type = (packetBytes.get() & 0x30) >> 4;
        if (InitialPacket.isInitial(type, Version.parse(version))) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-14.1
            // "A server MUST discard an Initial packet that is carried in a UDP
            //   datagram with a payload that is smaller than the smallest allowed
            //   maximum datagram size of 1200 bytes. "
            if (packetBytes.limit() >= 1200) {
                return !supportedVersionIds.contains(version);
            }
        }
        return false;
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
            VersionNegotiationPacket versionNegotiationPacket = new VersionNegotiationPacket(supportedVersions, dcid, scid);
            byte[] packetBytes = versionNegotiationPacket.generatePacketBytes(null);
            DatagramPacket datagram = new DatagramPacket(packetBytes, packetBytes.length, clientAddress.getAddress(), clientAddress.getPort());
            try {
                serverSocket.send(datagram);
                log.sent(Instant.now(), versionNegotiationPacket);
            } catch (IOException e) {
                log.error("Sending version negotiation packet failed", e);
            }
        }
    }

    private void closed(ServerConnectionImpl connection) {
        ServerConnectionProxy removedConnection = connectionRegistry.removeConnection(connection);
        removedConnection.dispose();
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

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private int port;
        private DatagramSocket socket;
        private InputStream certificateFile;
        private InputStream certificateKeyFile;
        private List<Version> supportedVersions = new ArrayList<>(List.of(Version.QUIC_version_1));
        private ServerConnectionConfig configuration = getDefaultConfiguration(true);
        private Logger log;
        private KeyStore keyStore;
        private String certificateAlias;
        private char[] privateKeyPassword;

        public Builder withPort(int port) {
            this.port = port;
            return this;
        }

        public Builder withSocket(DatagramSocket socket) {
            this.socket = socket;
            return this;
        }

        public Builder withCertificate(InputStream certificateFile, InputStream certificateKeyFile) {
            this.certificateFile = Objects.requireNonNull(certificateFile);
            this.certificateKeyFile = Objects.requireNonNull(certificateKeyFile);
            return this;
        }

        public Builder withKeyStore(KeyStore keyStore, String certificateAlias, char[] privateKeyPassword) {
            this.keyStore = Objects.requireNonNull(keyStore);
            this.certificateAlias = Objects.requireNonNull(certificateAlias);
            this.privateKeyPassword = Objects.requireNonNull(privateKeyPassword);
            return this;
        }

        public Builder withSupportedVersions(List<Version> supportedVersions) {
            this.supportedVersions.addAll(supportedVersions);
            return this;
        }

        public Builder withSupportedVersion(Version supportedVersion) {
            this.supportedVersions.add(supportedVersion);
            return this;
        }

        public Builder withConfiguration(ServerConnectionConfig configuration) {
            this.configuration = Objects.requireNonNull(configuration);
            return this;
        }

        public Builder withLogger(Logger log) {
            this.log = log;
            return this;
        }

        public ServerConnector build() throws Exception {
            if (port == 0) {
                throw new IllegalStateException("port number not set");
            }
            if (certificateFile == null && keyStore == null) {
                throw new IllegalStateException("server certificate not set");
            }

            if (socket == null) {
                socket = new DatagramSocket(port);
            }
            if (keyStore != null) {
                return new ServerConnector(socket, keyStore, certificateAlias, privateKeyPassword, supportedVersions, configuration, log);
            }
            else {
                return new ServerConnector(socket, certificateFile, certificateKeyFile, supportedVersions, configuration, log);
            }
        }
    }
}
