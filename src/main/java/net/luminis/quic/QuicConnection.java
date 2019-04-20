/*
 * Copyright © 2019 Peter Doornbosch
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

import net.luminis.tls.*;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static net.luminis.quic.EncryptionLevel.*;
import static net.luminis.tls.Tls13.generateKeys;


/**
 * Creates and maintains a QUIC connection with a QUIC server.
 */
public class QuicConnection implements PacketProcessor {

    enum Status {
        Idle,
        Handshaking,
        HandshakeError,
        Connected,
        Error
    }

    private final Logger log;
    private final Version quicVersion;
    private final Random random = new Random();
    private final String host;
    private final int port;
    private final TlsState tlsState;
    private final DatagramSocket socket;
    private final InetAddress serverAddress;
    private final int[] lastPacketNumber = new int[EncryptionLevel.values().length];
    private final Sender sender;
    private final Receiver receiver;
    private final ECPrivateKey privateKey;
    private final ECPublicKey publicKey;
    private volatile byte[] sourceConnectionId;
    private volatile byte[] destConnectionId;
    private volatile byte[] originalDestinationConnectionId;
    private volatile byte[] token;
    private final ConnectionSecrets connectionSecrets;
    private final List<CryptoStream> cryptoStreams = new ArrayList<>();
    private final Map<Integer, QuicStream> streams;
    private int nextStreamId;
    private volatile Status connectionState;
    private final CountDownLatch handshakeFinishedCondition = new CountDownLatch(1);
    private volatile TransportParameters transportParams;
    private Map<Integer, byte[]> destConnectionIds;
    private Map<Integer, byte[]> sourceConnectionIds;
    private KeepAliveActor keepAliveActor;
    private Consumer<QuicStream> serverStreamCallback;
    private String applicationProtocol;


    public QuicConnection(String host, int port, Logger log) throws UnknownHostException, SocketException {
        this(host, port, Version.IETF_draft_17, log);
    }

    public QuicConnection(String host, int port, Version quicVersion, Logger log) throws UnknownHostException, SocketException {
        log.info("Creating connection with " + host + ":" + port + " with " + quicVersion);
        this.host = host;
        this.port = port;
        serverAddress = InetAddress.getByName(host);
        this.quicVersion = quicVersion;
        this.log = log;

        socket = new DatagramSocket();
        sender = new Sender(socket, 1500, log, serverAddress, port, this);
        receiver = new Receiver(socket, 1500, log);
        tlsState = new QuicTlsState(quicVersion);
        connectionSecrets = new ConnectionSecrets(quicVersion, log);
        streams = new ConcurrentHashMap<>();
        sourceConnectionIds = new ConcurrentHashMap<>();
        destConnectionIds = new ConcurrentHashMap<>();

        try {
            ECKey[] keys = generateKeys("secp256r1");
            privateKey = (ECPrivateKey) keys[0];
            publicKey = (ECPublicKey) keys[1];
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate key pair.");
        }

        connectionState = Status.Idle;
    }

    /**
     * Set up the connection with the server.
     */
    public void connect(int connectionTimeout) throws IOException {
        connect(connectionTimeout, "hq-15");
    }

    public synchronized void connect(int connectionTimeout, String applicationProtocol) throws IOException {
        this.applicationProtocol = applicationProtocol;
        generateConnectionIds(8, 8);
        generateInitialKeys();

        receiver.start();
        sender.start(connectionSecrets);
        startReceiverLoop();

        startHandshake(applicationProtocol);

        try {
            boolean handshakeFinished = handshakeFinishedCondition.await(connectionTimeout, TimeUnit.MILLISECONDS);
            if (!handshakeFinished) {
                throw new ConnectException("Connection timed out");
            }
            else if (connectionState == Status.HandshakeError) {
                throw new ConnectException("Handshake error");
            }
        }
        catch (InterruptedException e) {
            throw new RuntimeException();  // Should not happen.
        }
    }

    public void keepAlive(int seconds) {
        if (connectionState != Status.Connected) {
            throw new IllegalStateException("keep alive can only be set when connected");
        }

        keepAliveActor = new KeepAliveActor(quicVersion, seconds, transportParams.getIdleTimeout(), this);
    }

    public void ping() {
        if (connectionState == Status.Connected) {
            QuicPacket packet = createPacket(App, new PingFrame(quicVersion));
            packet.frames.add(new Padding(20));  // TODO: find out minimum packet size, and let packet take care of it.
            send(packet, "ping");
        }
        else {
            throw new IllegalStateException("not connected");
        }
    }

    private void startReceiverLoop() {
        Thread receiverThread = new Thread(this::receiveAndProcessPackets, "receiver-loop");
        receiverThread.setDaemon(true);
        receiverThread.start();
    }

    private void receiveAndProcessPackets() {
        Thread currentThread = Thread.currentThread();
        int receivedPacketCounter = 0;

        try {
            while (! currentThread.isInterrupted()) {
                RawPacket rawPacket = receiver.get(15);
                if (rawPacket != null) {
                    Duration processDelay = Duration.between(rawPacket.getTimeReceived(), Instant.now());
                    log.raw("Start processing packet " + ++receivedPacketCounter + " (" + rawPacket.getLength() + " bytes)", rawPacket.getData(), 0, rawPacket.getLength());
                    log.debug("Packet process delay for packet #" + receivedPacketCounter + ": " + processDelay);

                    parsePackets(receivedPacketCounter, rawPacket.getTimeReceived(), rawPacket.getData());
                }
            }
        }
        catch (InterruptedException e) {
            log.debug("Terminating receiver loop because of interrupt");
        }
        catch (Exception error) {
            log.debug("Terminating receiver loop because of error");
            abortConnection(error);
        }
    }

    /**
     * Generate the initial connection id's for this connection.
     * Note that connection id's might change during the lifetime of a connection, and the dest connection id certainly will.
     * @param srcConnIdLength
     * @param dstConnIdLength
     */
    private void generateConnectionIds(int srcConnIdLength, int dstConnIdLength) {
        sourceConnectionId = new byte[srcConnIdLength];
        random.nextBytes(sourceConnectionId);
        log.debug("Source connection id", sourceConnectionId);
        sourceConnectionIds.put(0, sourceConnectionId);

        destConnectionId = new byte[dstConnIdLength];
        random.nextBytes(destConnectionId);
        log.info("Original destination connection id", destConnectionId);
        originalDestinationConnectionId = destConnectionId;
        destConnectionIds.put(0, destConnectionId);
    }

    private void generateInitialKeys() {
        connectionSecrets.computeInitialKeys(destConnectionId);
    }

    private void startHandshake(String applicationProtocol) {
        byte[] clientHello = createClientHello(host, publicKey, applicationProtocol);
        tlsState.clientHelloSend(privateKey, clientHello);

        InitialPacket clientHelloPacket = (InitialPacket) createPacket(EncryptionLevel.Initial, new CryptoFrame(quicVersion, clientHello));
        // Initial packet should at least be 1200 bytes (https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-14)
        clientHelloPacket.ensureSize(1200);

        connectionState = Status.Handshaking;
        sender.send(clientHelloPacket, "client hello");
    }

    void finishHandshake(TlsState tlsState) {
        if (tlsState.isServerFinished()) {
            FinishedMessage finishedMessage = new FinishedMessage(tlsState);
            CryptoFrame cryptoFrame = new CryptoFrame(quicVersion, finishedMessage.getBytes());
            QuicPacket finishedPacket = createPacket(Handshake, cryptoFrame);
            sender.send(finishedPacket, "client finished");
            tlsState.computeApplicationSecrets();
            connectionSecrets.computeApplicationSecrets(tlsState);

            connectionState = Status.Connected;
            handshakeFinishedCondition.countDown();
        }
    }

    QuicPacket createPacket(EncryptionLevel level, QuicFrame frame) {
        QuicPacket packet;
        switch (level) {
            case Initial:
                packet = new InitialPacket(quicVersion, sourceConnectionId, destConnectionId, token, frame);
                break;
            case Handshake:
                packet = new HandshakePacket(quicVersion, sourceConnectionId, destConnectionId, frame);
                break;
            case App:
                packet = new ShortHeaderPacket(quicVersion, destConnectionId, frame);
                break;
            default:
                throw new RuntimeException();  // Cannot happen, just here to satisfy the compiler.
        }
        return packet;
    }

    void parsePackets(int datagram, Instant timeReceived, ByteBuffer data) {
        int packetStart = data.position();

        try {
            QuicPacket packet;
            if (quicVersion.atLeast(Version.IETF_draft_17)) {
                packet = parsePacket(data);
            } else {
                packet = parsePacketPreDraft17(data);
            }

            log.received(timeReceived, datagram, packet);
            log.debug("Parsed packet with size " + (data.position() - packetStart) + "; " + data.remaining() + " bytes left.");

            // TODO: strictly speaking, processing packet received event, which includes generating acks, should be done after processing the packet itself, see
            // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-13.1
            // "A packet MUST NOT be acknowledged until packet protection has been
            //   successfully removed and all frames contained in the packet have been
            //   processed."
            sender.processPacketReceived(packet);
            packet.accept(this);

            if (data.position() < data.limit()) {
                parsePackets(datagram, timeReceived, data.slice());
            }
            else {
                // Processed all packets in the datagram. Select the "highest" level for ack (obviously a TODO)
                sender.packetProcessed(packet.getEncryptionLevel());
            }
        }
        catch (MissingKeysException noKeys) {
            log.debug("Discarding packets because of missing keys.");
        }
    }

    QuicPacket parsePacket(ByteBuffer data) throws MissingKeysException {
        int flags = data.get();
        int version = data.getInt();
        data.rewind();

        QuicPacket packet;

        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.4:
        // "A Version Negotiation packet ... will appear to be a packet using the long header, but
        //  will be identified as a Version Negotiation packet based on the
        //  Version field having a value of 0."
        if (version == 0) {
            packet = new VersionNegotationPacket().parse(data, log);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.5
        // "An Initial packet uses long headers with a type value of 0x0."
        else if ((flags & 0xf0) == 0xc0) {  // 1100 0000
            packet = new InitialPacket(quicVersion).parse(data, connectionSecrets, log);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.7
        // "A Retry packet uses a long packet header with a type value of 0x3"
        else if ((flags & 0xf0) == 0xf0) {  // 1111 0000
            // Retry packet....
            packet = new RetryPacket(quicVersion).parse(data, connectionSecrets, log);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.6
        // "A Handshake packet uses long headers with a type value of 0x2."
        else if ((flags & 0xf0) == 0xe0) {  // 1110 0000
            packet = new HandshakePacket(quicVersion).parse(data, connectionSecrets, log);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.2
        // "|  0x1 | 0-RTT Protected | Section 12.1 |"
        else if ((flags & 0xf0) == 0xd0) {  // 1101 0000
            // 0-RTT Protected
            throw new NotYetImplementedException();
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.3
        // "|0|1|S|R|R|K|P P|"
        else if ((flags & 0xc0) == 0x40) {  // 0100 0000
            // ShortHeader
            packet = new ShortHeaderPacket(quicVersion).parse(data, this, connectionSecrets, log);
        }
        else {
            throw new ProtocolError(String.format("Unknown Packet type; flags=%x", flags));
        }
        return packet;
    }

    QuicPacket parsePacketPreDraft17(ByteBuffer data) throws MissingKeysException {
        int flags = data.get();
        int version = data.getInt();
        data.rewind();

        QuicPacket packet;

        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.4:
        // "A Version Negotiation packet ... will appear to be a packet using the long header, but
        //  will be identified as a Version Negotiation packet based on the
        //  Version field having a value of 0."
        if (version == 0) {
            packet = new VersionNegotationPacket().parse(data, log);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.5
        // "An Initial packet uses long headers with a type value of 0x7F."
        else if ((flags & 0xff) == 0xff) {
            packet = new InitialPacket(quicVersion).parse(data, connectionSecrets, log);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.7
        // "A Retry packet uses a long packet header with a type value of 0x7E."
        else if ((flags & 0xff) == 0xfe) {
            // Retry packet....
            throw new NotYetImplementedException();
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.6
        // "A Handshake packet uses long headers with a type value of 0x7D."
        else if ((flags & 0xff) == 0xfd) {
            packet = new HandshakePacket(quicVersion).parse(data, connectionSecrets, log);
        }
        else if ((flags & 0xff) == 0xfc) {
            // 0-RTT Protected
            throw new NotYetImplementedException();
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.3
        // "The most significant bit (0x80) of octet 0 is set to 0 for the short header."
        else if ((flags & 0x80) == 0x00) {
            // ShortHeader
            packet = new ShortHeaderPacket(quicVersion).parse(data, this, connectionSecrets, log);
        }
        else {
            throw new ProtocolError(String.format("Unknown Packet type; flags=%x", flags));
        }
        return packet;
    }

    private CryptoStream getCryptoStream(EncryptionLevel encryptionLevel) {
        if (cryptoStreams.size() <= encryptionLevel.ordinal()) {
            for (int i = encryptionLevel.ordinal() - cryptoStreams.size(); i >= 0; i--) {
                cryptoStreams.add(new CryptoStream(quicVersion, this, encryptionLevel, connectionSecrets, tlsState, log));
            }
        }
        return cryptoStreams.get(encryptionLevel.ordinal());
    }

    private byte[] createClientHello(String host, ECPublicKey publicKey, String alpnProtocol) {
        boolean compatibilityMode = false;
        byte[][] supportedCiphers = new byte[][]{ TlsConstants.TLS_AES_128_GCM_SHA256 };

        Extension[] quicExtensions = new Extension[] {
                quicVersion.atLeast(Version.IETF_draft_17)?
                        new QuicTransportParametersExtension(quicVersion):
                        new QuicTransportParametersExtensionPreDraft17(quicVersion),
                new ECPointFormatExtension(),
                new ApplicationLayerProtocolNegotiationExtension(alpnProtocol),
        };
        return new ClientHello(host, publicKey, compatibilityMode, supportedCiphers, quicExtensions).getBytes();
    }

    @Override
    public void process(InitialPacket packet) {
        destConnectionId = packet.getSourceConnectionId();
        destConnectionIds.put(0, destConnectionId);
        processFrames(packet);
    }

    @Override
    public void process(HandshakePacket packet) {
        processFrames(packet);
    }

    @Override
    public void process(LongHeaderPacket packet) {
        processFrames(packet);
    }

    @Override
    public void process(ShortHeaderPacket packet) {
        processFrames(packet);
    }

    @Override
    public void process(VersionNegotationPacket packet) {
        log.info("Server doesn't support " + quicVersion + ", but only: " + ((VersionNegotationPacket) packet).getServerSupportedVersions().stream().collect(Collectors.joining(", ")));
        throw new VersionNegationFailure();
    }

    private volatile boolean processedRetryPacket = false;

    @Override
    public void process(RetryPacket packet) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-17.2.5
        // "Clients MUST discard Retry packets that contain an Original
        //   Destination Connection ID field that does not match the Destination
        //   Connection ID from its Initial packet"
        if (Arrays.equals(packet.getOriginalDestinationConnectionId(), destConnectionId)) {
            if (!processedRetryPacket) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-17.2.5
                // "A client MUST accept and process at most one Retry packet for each
                //   connection attempt.  After the client has received and processed an
                //   Initial or Retry packet from the server, it MUST discard any
                //   subsequent Retry packets that it receives."
                processedRetryPacket = true;

                token = packet.getRetryToken();
                destConnectionId = packet.getSourceConnectionId();
                destConnectionIds.put(0, destConnectionId);
                log.debug("Changing destination connection id into: " + ByteUtils.bytesToHex(destConnectionId));
                generateInitialKeys();

                synchronized (lastPacketNumber) {
                    lastPacketNumber[Initial.ordinal()] = 0;
                }

                // https://tools.ietf.org/html/draft-ietf-quic-recovery-18#section-6.2.1.1
                // "A Retry or Version Negotiation packet causes a client to send another
                //   Initial packet, effectively restarting the connection process and
                //   resetting congestion control..."
                sender.getCongestionController().reset();

                startHandshake(applicationProtocol);
            } else {
                log.debug("Ignoring RetryPacket, because already processed one.");
            }
        }
    }

    void processFrames(QuicPacket packet) {
        for (QuicFrame frame: packet.getFrames()) {
            if (frame instanceof CryptoFrame) {
                getCryptoStream(packet.getEncryptionLevel()).add((CryptoFrame) frame);
            }
            else if (frame instanceof AckFrame) {
                if (transportParams != null) {
                    ((AckFrame) frame).setDelayExponent(transportParams.getAckDelayExponent());
                }
                sender.process(frame, packet.getEncryptionLevel());
            }
            else if (frame instanceof StreamFrame) {
                int streamId = ((StreamFrame) frame).getStreamId();
                QuicStream stream = streams.get(streamId);
                if (stream != null) {
                    stream.add((StreamFrame) frame);
                }
                else {
                    if (streamId % 2 == 1) {
                        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-2.1
                        // "servers initiate odd-numbered streams"
                        log.info("Receiving data for server-initiated stream " + streamId);
                        stream = new QuicStream(quicVersion, streamId, this, log);
                        streams.put(streamId, stream);
                        stream.add((StreamFrame) frame);
                        if (serverStreamCallback != null) {
                            serverStreamCallback.accept(stream);
                        }
                    }
                    else {
                        log.error("Receiving frame for non-existant stream " + streamId);
                    }
                }
            }
            else if (frame instanceof NewConnectionIdFrame) {
                destConnectionIds.put(((NewConnectionIdFrame) frame).getSequenceNr(), ((NewConnectionIdFrame) frame).getConnectionId());
            }
            else if (frame instanceof RetireConnectionIdFrame) {
                retireConnectionId(((RetireConnectionIdFrame) frame).getSequenceNr());
            }
            else {
                log.debug("Ignoring " + frame);
            }
        }
    }

    private void handleIOError(IOException e) {
        System.out.println("Fatal: IO error " + e);
        System.exit(1);
    }

    public QuicStream createStream(boolean bidirectional) {
        int streamId = generateClientStreamId(bidirectional);
        QuicStream stream = new QuicStream(quicVersion, streamId, this, log);
        streams.put(streamId, stream);
        return stream;
    }

    public void close() {
        sender.shutdown();
        if (keepAliveActor != null) {
            keepAliveActor.shutdown();
        }
        // TODO
    }

    private synchronized int generateClientStreamId(boolean bidirectional) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-2.1:
        // "0x0  | Client-Initiated, Bidirectional"
        int id = (nextStreamId << 2) + 0x00;
        nextStreamId++;
        return id;
    }

    void send(QuicFrame frame) {
        QuicPacket packet = createPacket(App, frame);
        sender.send(packet, "application data");
    }

    void send(QuicPacket packet, String logMessage) {
        if (logMessage == null) {
            logMessage = "application data";
        }
        sender.send(packet, logMessage);
    }

    int getMaxPacketSize() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-14.1:
        // "An endpoint SHOULD use Datagram Packetization Layer PMTU Discovery
        //   ([DPLPMTUD]) or implement Path MTU Discovery (PMTUD) [RFC1191]
        //   [RFC8201] ..."
        // "In the absence of these mechanisms, QUIC endpoints SHOULD NOT send IP
        //   packets larger than 1280 bytes.  Assuming the minimum IP header size,
        //   this results in a QUIC maximum packet size of 1232 bytes for IPv6 and
        //   1252 bytes for IPv4."
        // As it is not know (yet) whether running over IP4 or IP6, take the smallest of the two:
        return 1232;
    }

    int getMaxShortHeaderPacketOverhead() {
        return 1  // flag byte
                + destConnectionId.length
                + 4  // max packet number size, in practice this will be mostly 1
                + 16 // encryption overhead
        ;
    }

    void setTransportParameters(TransportParameters transportParameters) {
        transportParams = transportParameters;
        if (processedRetryPacket) {
            if (transportParameters.getOriginalConnectionId() == null ||
                    ! Arrays.equals(originalDestinationConnectionId, transportParameters.getOriginalConnectionId())) {
                signalConnectionError(QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR);
            }
        }
        else {
            if (transportParameters.getOriginalConnectionId() != null) {
                signalConnectionError(QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR);
            }
        }
    }

    void signalConnectionError(QuicConstants.TransportErrorCode transportError) {
        log.info("ConnectionError " + transportError);
        // TODO: close connection with a frame type of 0x1c
    }

    private void abortConnection(Exception error) {
        if (connectionState == Status.Handshaking) {
            connectionState = Status.HandshakeError;
        }
        else {
            connectionState = Status.Error;
        }

        log.error("Aborting connection because of error", error);
        handshakeFinishedCondition.countDown();
        sender.shutdown();
        receiver.shutdown();
        streams.values().stream().forEach(s -> s.abort());
    }

    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-5.1.2
    // "An endpoint can change the connection ID it uses for a peer to
    //   another available one at any time during the connection. "
    public byte[] nextDestinationConnectionId() {
        int currentIndex = destConnectionIds.entrySet().stream()
                .filter(entry -> entry.getValue().equals(destConnectionId))
                .mapToInt(entry -> entry.getKey())
                .findFirst().orElse(0);
        byte[] newConnectionId = destConnectionIds.get(currentIndex + 1);
        log.debug("Switching to next destination connection id: " + ByteUtils.bytesToHex(newConnectionId));
        destConnectionId = newConnectionId;
        return newConnectionId;
    }

    public byte[][] newConnectionIds(int count) {
        QuicPacket packet = createPacket(App, null);
        byte[][] newConnectionIds = new byte[3][];

        for (int i = 0; i < count; i++) {
            byte[] newSourceConnectionId = new byte[sourceConnectionId.length];
            random.nextBytes(newSourceConnectionId);
            newConnectionIds[i] = newSourceConnectionId;
            int sequenceNr = sourceConnectionIds.size();
            sourceConnectionIds.put(sequenceNr, newSourceConnectionId);
            log.debug("New generated source connection id", newSourceConnectionId);
            packet.addFrame(new NewConnectionIdFrame(quicVersion, sequenceNr, newSourceConnectionId));
        }

        send(packet, "new connection id's");
        return newConnectionIds;
    }

    private void retireConnectionId(int sequenceNr) {
        if (sourceConnectionIds.containsKey(sequenceNr)) {
            sourceConnectionIds.put(sequenceNr, null);
        }
    }


    public byte[] getSourceConnectionId() {
        return sourceConnectionId;
    }

    public byte[] getDestinationConnectionId() {
        return destConnectionId;
    }

    public Map<Integer, byte[]> getDestinationConnectionIds() {
        return destConnectionIds;
    }

    public void setServerStreamCallback(Consumer<QuicStream> streamProcessor) {
        this.serverStreamCallback = streamProcessor;
    }

}
