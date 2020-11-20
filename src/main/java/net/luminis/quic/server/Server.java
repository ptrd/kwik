/*
 * Copyright © 2020 Peter Doornbosch
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
package net.luminis.quic.server;

import net.luminis.quic.RawPacket;
import net.luminis.quic.Receiver;
import net.luminis.quic.UnknownVersionException;
import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.packet.VersionNegotiationPacket;
import net.luminis.tls.handshake.TlsServerEngineFactory;
import net.luminis.tls.util.ByteUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Simple QUIC server.
 */
public class Server {

    private static final int MINIMUM_LONG_HEADER_LENGTH = 1 + 4 + 1 + 0 + 1 + 0;
    private static final int CONNECTION_ID_LENGTH = 4;

    private final Receiver receiver;
    private final Logger log;
    private final List<Version> supportedVersions;
    private final List<Integer> supportedVersionIds;
    private final DatagramSocket serverSocket;
    private Integer initalRtt = 100;
    private Map<ConnectionSource, ServerConnection> currentConnections;
    private TlsServerEngineFactory tlsEngineFactory;
    private final ServerConnectionFactory serverConnectionFactory;


    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Usage: cert file, cert key file, port number");
            System.exit(1);
        }
        File certificateFile = new File(args[0]);
        if (!certificateFile.exists()) {
            System.err.println("Cannot open certificate file " + args[0]);
            System.exit(1);
        }
        File certificateKeyFile = new File(args[1]);
        if (!certificateKeyFile.exists()) {
            System.err.println("Cannot open certificate file " + args[0]);
            System.exit(1);
        }
        int port = Integer.parseInt(args[2]);

        new Server(port, new FileInputStream(certificateFile), new FileInputStream(certificateKeyFile), List.of(Version.getDefault())).start();
    }

    public Server(int port, InputStream certificateFile, InputStream certificateKeyFile, List<Version> supportedVersions) throws Exception {
        this(new DatagramSocket(port), certificateFile, certificateKeyFile, supportedVersions);
    }

    public Server(DatagramSocket socket, InputStream certificateFile, InputStream certificateKeyFile, List<Version> supportedVersions) throws Exception {
        serverSocket = socket;
        this.supportedVersions = supportedVersions;
        log = new SysOutLogger();
        log.logWarning(true);
        log.logPackets(true);
        log.logInfo(true);

        tlsEngineFactory = new TlsServerEngineFactory(certificateFile, certificateKeyFile);
        serverConnectionFactory = new ServerConnectionFactory(CONNECTION_ID_LENGTH, serverSocket, tlsEngineFactory, initalRtt, this::removeConnection, log);

        supportedVersionIds = supportedVersions.stream().map(version -> version.getId()).collect(Collectors.toList());
        currentConnections = new HashMap<>();
        receiver = new Receiver(serverSocket, 1200, log, exception -> System.exit(9));
    }

    private void start() {
        receiver.start();

        new Thread(this::receiveLoop, "server receive loop").start();
    }

    private void receiveLoop() {
        try {
            while (true) {
                RawPacket rawPacket = receiver.get((int) Duration.ofDays(10 * 365).toSeconds());
                process(rawPacket);
            }
        } catch (InterruptedException e) {
            log.error("receiver interrupted (ignoring)");
        }
    }

    void process(RawPacket rawPacket) {
        ByteBuffer data = rawPacket.getData();
        int flags = data.get();
        data.rewind();
        if ((flags & 0b1100_0000) == 0b1100_0000) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2
            // "Header Form:  The most significant bit (0x80) of byte 0 (the first byte) is set to 1 for long headers."
            processLongHeaderPacket(new InetSocketAddress(rawPacket.getAddress(), rawPacket.getPort()), flags, data);
        } else if ((flags & 0b1100_0000) == 0b0100_0000) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.3
            // "Header Form:  The most significant bit (0x80) of byte 0 is set to 0 for the short header.
            processShortHeaderPacket(data);
        } else {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.3
            // "The next bit (0x40) of byte 0 is set to 1. Packets containing a zero value for this bit are not valid
            //  packets in this version and MUST be discarded."
            log.warn(String.format("Invalid Quic packet (flags: %02x) is discarded", flags));
        }
    }

    private void processLongHeaderPacket(InetSocketAddress clientAddress, int flags, ByteBuffer data) {
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
            if (data.remaining() >= dcidLength) {
                byte[] dcid = new byte[dcidLength];
                data.get(dcid);
                int scidLength = data.get() & 0xff;
                byte[] scid = new byte[scidLength];
                data.get(scid);
                data.rewind();

                Optional<ServerConnection> connection = isExistingConnection(clientAddress, dcid);
                if (connection.isEmpty()) {
                    if (mightStartNewConnection(data, version, dcid)) {
                        connection = Optional.of(createNewConnection(version, clientAddress, scid, dcid));
                    } else if (initialWithUnspportedVersion(data, version)) {
                        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-6
                        // "A server sends a Version Negotiation packet in response to each packet that might initiate a new connection;"
                        sendVersionNegotiationPacket(clientAddress, data, dcidLength);
                    }
                }
                connection.ifPresent(c -> c.parsePackets(0, Instant.now(), data));
            }
        }
    }

    private void processShortHeaderPacket(ByteBuffer data) {
        System.out.println("Receiving short header packet (" + data.remaining() + " bytes)");
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
        int flags = packetBytes.get() & 0xff;
        if ((flags & 0b1111_0000) == 0b1100_0000) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-14.1
            // "A server MUST discard an Initial packet that is carried in a UDP
            //   datagram with a payload that is smaller than the smallest allowed
            //   maximum datagram size of 1200 bytes. "
            if (packetBytes.limit() >= 1200) {
                return !supportedVersions.contains(version);
            }
        }
        return false;
    }

    private ServerConnection createNewConnection(int versionValue, InetSocketAddress clientAddress, byte[] scid, byte[] dcid) {
        try {
            Version version = Version.parse(versionValue);
            log.info("Creating new connection with version " + version + " for odcid " + ByteUtils.bytesToHex(dcid));
            ServerConnection newConnection = serverConnectionFactory.createNewConnection(version, clientAddress, scid, dcid);
            currentConnections.put(new ConnectionSource(newConnection.getSourceConnectionId()), newConnection);
            return newConnection;
        } catch (UnknownVersionException e) {
            // Impossible, as it only gets here if the given version is supported, so it is a known version.
            throw new RuntimeException();
        }
    }

    private void removeConnection(byte[] cid) {
        ServerConnection removed = currentConnections.remove(new ConnectionSource(cid));
        if (removed == null) {
            log.error("Cannot remove connection with cid " + ByteUtils.bytesToHex(cid));
        }
        else if (! removed.isClosed()) {
            log.error("Removed connection with cid " + ByteUtils.bytesToHex(cid) + " that is not closed...");
        }
    }

    private Optional<ServerConnection> isExistingConnection(InetSocketAddress clientAddress, byte[] dcid) {
        return Optional.ofNullable(currentConnections.get(new ConnectionSource(dcid)));
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
            byte[] packetBytes = versionNegotiationPacket.generatePacketBytes(0, null);
            DatagramPacket datagram = new DatagramPacket(packetBytes, packetBytes.length, clientAddress.getAddress(), clientAddress.getPort());
            try {
                serverSocket.send(datagram);
            } catch (IOException e) {
                log.error("Sending version negotiation packet failed", e);
            }
        }
    }

}
