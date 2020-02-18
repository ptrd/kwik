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

import net.luminis.quic.cid.ConnectionIdInfo;
import net.luminis.quic.cid.DestinationConnectionIdRegistry;
import net.luminis.quic.cid.SourceConnectionIdRegistry;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.*;
import net.luminis.quic.stream.FlowControl;
import net.luminis.quic.stream.QuicStream;
import net.luminis.quic.stream.StreamManager;
import net.luminis.tls.*;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static net.luminis.quic.EncryptionLevel.*;
import static net.luminis.tls.Tls13.generateKeys;


/**
 * Creates and maintains a QUIC connection with a QUIC server.
 */
public class QuicConnectionImpl implements QuicConnection, PacketProcessor {

    enum Status {
        Idle,
        Handshaking,
        HandshakeError,
        Connected,
        Closing,
        Draining,
        Error
    }

    private final Logger log;
    private final Version quicVersion;
    private final String host;
    private final int port;
    private final NewSessionTicket sessionTicket;
    private final TlsState tlsState;
    private final DatagramSocket socket;
    private final InetAddress serverAddress;
    private final Sender sender;
    private final Receiver receiver;
    private final StreamManager streamManager;
    private final ECPrivateKey privateKey;
    private final ECPublicKey publicKey;
    private volatile byte[] token;
    private final ConnectionSecrets connectionSecrets;
    private final List<CryptoStream> cryptoStreams = new ArrayList<>();
    private volatile Status connectionState;
    private final CountDownLatch handshakeFinishedCondition = new CountDownLatch(1);
    private final CountDownLatch drainingSignal = new CountDownLatch(1);
    private volatile TransportParameters peerTransportParams;
    private volatile TransportParameters transportParams;
    private volatile FlowControl flowController;
    private DestinationConnectionIdRegistry destConnectionIds;
    private SourceConnectionIdRegistry sourceConnectionIds;
    private KeepAliveActor keepAliveActor;
    private String applicationProtocol;
    private long flowControlMax;
    private long flowControlLastAdvertised;
    private long flowControlIncrement;
    private long largestPacketNumber;
    private final List<NewSessionTicket> newSessionTickets = Collections.synchronizedList(new ArrayList<>());


    public QuicConnectionImpl(String host, int port, Logger log) throws UnknownHostException, SocketException {
        this(host, port, Version.getDefault(), log);
    }

    public QuicConnectionImpl(String host, int port, Version quicVersion, Logger log) throws UnknownHostException, SocketException {
        this(host, port, null, quicVersion, log, null);
    }

    public QuicConnectionImpl(String host, int port, NewSessionTicket sessionTicket, Version quicVersion, Logger log, Path secretsFile) throws UnknownHostException, SocketException {
        this(host, port, sessionTicket, quicVersion, log, host, secretsFile);
        if (! quicVersion.atLeast(Version.IETF_draft_23)) {
            throw new IllegalArgumentException("Quic version " + quicVersion + " not supported");
        }
    }

    public QuicConnectionImpl(String host, int port, NewSessionTicket sessionTicket, Version quicVersion, Logger log, String proxyHost, Path secretsFile) throws UnknownHostException, SocketException {
        log.info("Creating connection with " + host + ":" + port + " with " + quicVersion);
        this.host = host;
        this.port = port;
        serverAddress = InetAddress.getByName(proxyHost);
        this.sessionTicket = sessionTicket;
        this.quicVersion = quicVersion;
        this.log = log;

        socket = new DatagramSocket();
        sender = new Sender(socket, 1500, log, serverAddress, port, this);
        receiver = new Receiver(this, socket, 1500, log);
        streamManager = new StreamManager(this, log);
        tlsState = sessionTicket == null? new QuicTlsState(quicVersion): new QuicTlsState(quicVersion, sessionTicket);
        connectionSecrets = new ConnectionSecrets(quicVersion, secretsFile, log);
        sourceConnectionIds = new SourceConnectionIdRegistry(log);
        destConnectionIds = new DestinationConnectionIdRegistry(log);
        transportParams = new TransportParameters(60, 250_000, 3 , 3);
        flowControlMax = transportParams.getInitialMaxData();
        flowControlLastAdvertised = flowControlMax;
        flowControlIncrement = flowControlMax / 10;

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
        connect(connectionTimeout, null);
    }

    public void connect(int connectionTimeout, TransportParameters transportParameters) throws IOException {
        String alpn = "hq-" + quicVersion.toString().substring(quicVersion.toString().length() - 2);
        connect(connectionTimeout, alpn, transportParameters);
    }

    public synchronized void connect(int connectionTimeout, String applicationProtocol, TransportParameters transportParameters) throws IOException {
        this.applicationProtocol = applicationProtocol;
        if (transportParameters != null) {
            this.transportParams = transportParameters;
        }

        log.info("Original destination connection id", destConnectionIds.getCurrent());
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
            else if (connectionState != Status.Connected) {
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

        keepAliveActor = new KeepAliveActor(quicVersion, seconds, (int) peerTransportParams.getMaxIdleTimeout(), this);
    }

    public void ping() {
        if (connectionState == Status.Connected) {
            QuicPacket packet = createPacket(App, new PingFrame(quicVersion));
            packet.getFrames().add(new Padding(20));  // TODO: find out minimum packet size, and let packet take care of it.
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
                    log.debug("Processing delay for packet #" + receivedPacketCounter + ": " + processDelay.toMillis() + " ms");

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

    private void generateInitialKeys() {
        connectionSecrets.computeInitialKeys(destConnectionIds.getCurrent());
    }

    private void startHandshake(String applicationProtocol) {
        byte[] clientHello = createClientHello(host, publicKey, applicationProtocol);
        tlsState.clientHelloSend(privateKey, clientHello);

        InitialPacket clientHelloPacket = (InitialPacket) createPacket(EncryptionLevel.Initial, new CryptoFrame(quicVersion, clientHello));
        // Initial packet should at least be 1200 bytes (https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-14)
        clientHelloPacket.ensureSize(1200);

        connectionState = Status.Handshaking;
        sender.send(clientHelloPacket, "client hello", p -> {});
    }

    void finishHandshake(TlsState tlsState) {
        if (tlsState.isServerFinished()) {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-23#section-4.9.1
            // "a client MUST discard Initial keys when it first sends a Handshake packet"
            // TODO tlsState.discardKeys(Initial);
            // "Endpoints MUST NOT send Initial packets after this point. This results in abandoning loss recovery state
            // for the Initial encryption level and ignoring any outstanding Initial packets."
            sender.stopRecovery(PnSpace.Initial);

            FinishedMessage finishedMessage = new FinishedMessage(tlsState);
            CryptoFrame cryptoFrame = new CryptoFrame(quicVersion, finishedMessage.getBytes());
            QuicPacket finishedPacket = createPacket(Handshake, cryptoFrame);
            sender.send(finishedPacket, "client finished", p -> {});
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
                packet = new InitialPacket(quicVersion, sourceConnectionIds.getCurrent(), destConnectionIds.getCurrent(), token, frame);
                break;
            case Handshake:
                packet = new HandshakePacket(quicVersion, sourceConnectionIds.getCurrent(), destConnectionIds.getCurrent(), frame);
                break;
            case App:
                packet = new ShortHeaderPacket(quicVersion, destConnectionIds.getCurrent(), frame);
                break;
            default:
                throw new RuntimeException();  // Cannot happen, just here to satisfy the compiler.
        }
        return packet;
    }

    void parsePackets(int datagram, Instant timeReceived, ByteBuffer data) {
        int packetStart = data.position();
        int packetSize = 0;
        EncryptionLevel highestEncryptionLevelInPacket = null;

        QuicPacket packet;
        try {
            packet = parsePacket(data);
            packetSize = data.position() - packetStart;
            if (highestEncryptionLevelInPacket == null || packet.getEncryptionLevel().higher(highestEncryptionLevelInPacket)) {
                highestEncryptionLevelInPacket = packet.getEncryptionLevel();
            }

            log.received(timeReceived, datagram, packet);
            log.debug("Parsed packet with size " + (data.position() - packetStart) + "; " + data.remaining() + " bytes left.");
            processPacket(timeReceived, packet);
        }
        catch (DecryptionException | MissingKeysException cannotParse) {
            packetSize = data.position() - packetStart;
            // https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-12.2
            // "if decryption fails (...), the receiver (...) MUST attempt to process the remaining packets."
            log.error("Discarding packet (" + packetSize + " bytes) that cannot be decrypted (" + cannotParse + ")");
        }

        if (packetSize > 0 && data.position() < data.limit()) {  
            parsePackets(datagram, timeReceived, data.slice());
        }
        else {
            // Processed all packets in the datagram. Select the "highest" level for ack.
            if (highestEncryptionLevelInPacket != null)
                sender.packetProcessed(highestEncryptionLevelInPacket);
        }
    }

    QuicPacket parsePacket(ByteBuffer data) throws MissingKeysException, DecryptionException {
        int flags = data.get();
        int version = data.getInt();
        data.rewind();

        QuicPacket packet;

        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.4:
        // "A Version Negotiation packet ... will appear to be a packet using the long header, but
        //  will be identified as a Version Negotiation packet based on the
        //  Version field having a value of 0."
        if (version == 0) {
            packet = new VersionNegotiationPacket(quicVersion);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.5
        // "An Initial packet uses long headers with a type value of 0x0."
        else if ((flags & 0xf0) == 0xc0) {  // 1100 0000
            packet = new InitialPacket(quicVersion);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.7
        // "A Retry packet uses a long packet header with a type value of 0x3"
        else if ((flags & 0xf0) == 0xf0) {  // 1111 0000
            // Retry packet....
            packet = new RetryPacket(quicVersion);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.6
        // "A Handshake packet uses long headers with a type value of 0x2."
        else if ((flags & 0xf0) == 0xe0) {  // 1110 0000
            packet = new HandshakePacket(quicVersion);
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
            packet = new ShortHeaderPacket(quicVersion);
        }
        else {
            throw new ProtocolError(String.format("Unknown Packet type; flags=%x", flags));
        }

        if (packet.getEncryptionLevel() != null) {
            Keys keys = connectionSecrets.getServerSecrets(packet.getEncryptionLevel());
            if (keys == null) {
                // Could happen when, due to packet reordering, the first short header packet arrives before handshake is finished.
                // https://tools.ietf.org/html/draft-ietf-quic-tls-18#section-5.7
                // "Due to reordering and loss, protected packets might be received by an
                //   endpoint before the final TLS handshake messages are received."
                throw new MissingKeysException(packet.getEncryptionLevel());
            }
            packet.parse(data, keys, largestPacketNumber, log, sourceConnectionIds.getConnectionIdlength());
        }
        else {
            packet.parse(data, null, largestPacketNumber, log, 0);
        }

        if (packet.getPacketNumber() != null && packet.getPacketNumber() > largestPacketNumber) {
            largestPacketNumber = packet.getPacketNumber();
        }
        return packet;
    }

    private void processPacket(Instant timeReceived, QuicPacket packet) {
        // TODO: strictly speaking, processing packet received event, which includes generating acks, should be done after processing the packet itself, see
        // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-13.1
        // "A packet MUST NOT be acknowledged until packet protection has been
        //   successfully removed and all frames contained in the packet have been
        //   processed."
        sender.processPacketReceived(packet);
        packet.accept(this, timeReceived);
    }

    private CryptoStream getCryptoStream(EncryptionLevel encryptionLevel) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-19.6
        // "There is a separate flow of cryptographic handshake data in each
        //   encryption level"
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

        List<Extension> quicExtensions = new ArrayList<>();
        quicExtensions.add(new QuicTransportParametersExtension(quicVersion, transportParams));
        quicExtensions.add(new ApplicationLayerProtocolNegotiationExtension(alpnProtocol));

        if (sessionTicket != null) {
            quicExtensions.add(new ClientHelloPreSharedKeyExtension(tlsState, sessionTicket));
        }

        ClientHello clientHello = new ClientHello(host, publicKey, compatibilityMode, supportedCiphers, quicExtensions);
        connectionSecrets.setClientRandom(clientHello.getClientRandom());
        return clientHello.getBytes();
    }

    @Override
    public void process(InitialPacket packet, Instant time) {
        destConnectionIds.replaceInitialConnectionId(packet.getSourceConnectionId());
        processFrames(packet, time);
    }

    @Override
    public void process(HandshakePacket packet, Instant time) {
        processFrames(packet, time);
    }

    @Override
    public void process(LongHeaderPacket packet, Instant time) {
        processFrames(packet, time);
    }

    @Override
    public void process(ShortHeaderPacket packet, Instant time) {
        if (sourceConnectionIds.registerUsedConnectionId(packet.getDestinationConnectionId())) {
            // New connection id, not used before.
            // https://tools.ietf.org/html/draft-ietf-quic-transport-25#section-5.1.1
            // "If an endpoint provided fewer connection IDs than the
            //   peer's active_connection_id_limit, it MAY supply a new connection ID
            //   when it receives a packet with a previously unused connection ID."
            if (! sourceConnectionIds.limitReached()) {
                newConnectionIds(1, 0);
            }
        }
        processFrames(packet, time);
    }

    @Override
    public void process(VersionNegotiationPacket packet, Instant time) {
        log.info("Server doesn't support " + quicVersion + ", but only: " + ((VersionNegotiationPacket) packet).getServerSupportedVersions().stream().collect(Collectors.joining(", ")));
        throw new VersionNegotiationFailure();
    }

    private volatile boolean processedRetryPacket = false;

    @Override
    public void process(RetryPacket packet, Instant time) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-17.2.5
        // "Clients MUST discard Retry packets that contain an Original
        //   Destination Connection ID field that does not match the Destination
        //   Connection ID from its Initial packet"
        if (packet.validateIntegrityTag(destConnectionIds.getCurrent())) {
            if (!processedRetryPacket) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-17.2.5
                // "A client MUST accept and process at most one Retry packet for each
                //   connection attempt.  After the client has received and processed an
                //   Initial or Retry packet from the server, it MUST discard any
                //   subsequent Retry packets that it receives."
                processedRetryPacket = true;

                token = packet.getRetryToken();
                byte[] destConnectionId = packet.getSourceConnectionId();
                destConnectionIds.replaceInitialConnectionId(destConnectionId);
                log.debug("Changing destination connection id into: " + ByteUtils.bytesToHex(destConnectionId));
                generateInitialKeys();

                // https://tools.ietf.org/html/draft-ietf-quic-recovery-18#section-6.2.1.1
                // "A Retry or Version Negotiation packet causes a client to send another
                //   Initial packet, effectively restarting the connection process and
                //   resetting congestion control..."
                sender.getCongestionController().reset();

                startHandshake(applicationProtocol);
            } else {
                log.error("Ignoring RetryPacket, because already processed one.");
            }
        }
        else {
            log.error("Discarding Retry packet, because integrity tag is invalid.");
        }
    }

    void processFrames(QuicPacket packet, Instant timeReceived) {
        for (QuicFrame frame: packet.getFrames()) {
            if (frame instanceof CryptoFrame) {
                getCryptoStream(packet.getEncryptionLevel()).add((CryptoFrame) frame);
                log.receivedPacketInfo(getCryptoStream(packet.getEncryptionLevel()).toString());
            }
            else if (frame instanceof AckFrame) {
                if (peerTransportParams != null) {
                    ((AckFrame) frame).setDelayExponent(peerTransportParams.getAckDelayExponent());
                }
                sender.process(frame, packet.getPnSpace(), timeReceived);
            }
            else if (frame instanceof StreamFrame) {
                streamManager.process(frame, packet.getPnSpace(), timeReceived);
            }
            else if (frame instanceof MaxStreamDataFrame) {
                flowController.process(frame, packet.getPnSpace(), timeReceived);
            }
            else if (frame instanceof MaxDataFrame) {
                flowController.process(frame, packet.getPnSpace(), timeReceived);
            }
            else if (frame instanceof MaxStreamsFrame) {
                streamManager.process(frame, packet.getPnSpace(), timeReceived);
            }
            else if (frame instanceof NewConnectionIdFrame) {
                registerNewDestinationConnectionId((NewConnectionIdFrame) frame);
            }
            else if (frame instanceof RetireConnectionIdFrame) {
                retireSourceConnectionId((RetireConnectionIdFrame) frame);
            }
            else if (frame instanceof ConnectionCloseFrame) {
                ConnectionCloseFrame close = (ConnectionCloseFrame) frame;
                handlePeerClosing(close);
            }
            else if (frame instanceof PathChallengeFrame) {
                PathResponseFrame response = new PathResponseFrame(quicVersion, ((PathChallengeFrame) frame).getData());
                send(response, f -> {});
            }
            else if (frame instanceof HandshakeDoneFrame) {
                sender.stopRecovery(PnSpace.Handshake);
                // TODO: discard handshake keys:
                // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-4.10.2
                // "An endpoint MUST discard its handshake keys when the TLS handshake is confirmed"
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
        return streamManager.createStream(bidirectional);
    }

    public void close() {
        if (connectionState == Status.Closing || connectionState == Status.Draining) {
            log.debug("Already closing");
            return;
        }
        if (keepAliveActor != null) {
            keepAliveActor.shutdown();
        }
        sender.stop();
        connectionState = Status.Closing;
        streamManager.abortAll();
        send(new ConnectionCloseFrame(quicVersion), f -> {});

        int closingPeriod = 3 * sender.getPto();
        log.debug("closing/draining for " + closingPeriod + " ms");
        try {
            drainingSignal.await(closingPeriod, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {}

        log.debug("leaving draining state (terminating)");
        terminate();
    }

    private void handlePeerClosing(ConnectionCloseFrame closing) {
        if (connectionState != Status.Closing) {
            if (closing.hasError()) {
                log.error("Connection closed by peer with " + determineClosingErrorMessage(closing));
            }
            else {
                log.info("Peer is closing");
            }
            // https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-10.3
            // "An endpoint that receives a CONNECTION_CLOSE frame
            //   MAY send a single packet containing a CONNECTION_CLOSE frame before
            //   entering the draining state, using a CONNECTION_CLOSE frame and a
            //   NO_ERROR code if appropriate."
            if (connectionState == Status.Connected) {   // Only if we have Application keys  TODO: also when no Application keys available
                send(new ConnectionCloseFrame(quicVersion), f -> {});  // TODO: number of connection close packets sent should be limited.
            }
            else if (connectionState == Status.Handshaking) {
                connectionState = Status.HandshakeError;
                handshakeFinishedCondition.countDown();
            }
            connectionState = Status.Draining;
            // We're done!
            terminate();
        }
        else if (connectionState == Status.Closing) {
            if (closing.hasError()) {
                log.error("Peer confirmed closing with " + determineClosingErrorMessage(closing));
            }
            else {
                log.info("Peer confirmed closing; entering draining state.");
            }
            connectionState = Status.Draining;
            drainingSignal.countDown();
        }
    }

    private String determineClosingErrorMessage(ConnectionCloseFrame closing) {
        if (closing.hasTransportError()) {
            if (closing.hasTlsError()) {
                return "TLS error " + closing.getTlsError() + (closing.hasReasonPhrase()? ": " + closing.getReasonPhrase():"");
            }
            else {
                return "transport error " + closing.getErrorCode() + (closing.hasReasonPhrase()? ": " + closing.getReasonPhrase():"");
            }
        }
        else if (closing.hasApplicationProtocolError()) {
            return "application protocol error " + closing.getErrorCode() + (closing.hasReasonPhrase()? ": " + closing.getReasonPhrase():"");
        }
        else {
            return "";
        }
    }

    private void terminate() {
        sender.shutdown();
        receiver.shutdown();
        socket.close();
    }

    public void send(QuicFrame frame, Consumer<QuicFrame> lostFrameCallback) {
        QuicPacket packet = createPacket(App, frame);
        sender.send(packet, "application data", p -> lostFrameCallback.accept(p.getFrames().get(0)));
    }

    void send(QuicPacket packet, String logMessage) {
        if (logMessage == null) {
            logMessage = "application data";
        }
        sender.send(packet, logMessage, p -> {});
    }

    public void slideFlowControlWindow(int size) {
        flowControlMax += size;
        if (flowControlMax - flowControlLastAdvertised > flowControlIncrement) {
            send(new MaxDataFrame(flowControlMax), f -> {});
            flowControlLastAdvertised = flowControlMax;
        }
    }

    public void changeAddress() {
        try {
            DatagramSocket newSocket = new DatagramSocket();
            sender.changeAddress(newSocket);
            receiver.changeAddress(newSocket);
            log.info("Changed local address to " + newSocket.getLocalPort());
        } catch (SocketException e) {
            // Fairly impossible, as we created a socket on an ephemeral port
            log.error("Changing local address failed", e);
        }
    }



    public int getMaxPacketSize() {
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

    public int getMaxShortHeaderPacketOverhead() {
        return 1  // flag byte
                + destConnectionIds.getConnectionIdlength()
                + 4  // max packet number size, in practice this will be mostly 1
                + 16 // encryption overhead
        ;
    }

    public TransportParameters getTransportParameters() {
        return transportParams;
    }

    public TransportParameters getPeerTransportParameters() {
        return peerTransportParams;
    }

    void setPeerTransportParameters(TransportParameters transportParameters) {
        peerTransportParams = transportParameters;
        flowController = new FlowControl(peerTransportParams.getInitialMaxData(),
                peerTransportParams.getInitialMaxStreamDataBidiLocal(),
                peerTransportParams.getInitialMaxStreamDataBidiRemote(),
                peerTransportParams.getInitialMaxStreamDataUni(),
                log);
        streamManager.setFlowController(flowController);

        streamManager.setInitialMaxStreamsBidi(peerTransportParams.getInitialMaxStreamsBidi());
        streamManager.setInitialMaxStreamsUni(peerTransportParams.getInitialMaxStreamsUni());

        sender.setReceiverMaxAckDelay(peerTransportParams.getMaxAckDelay());
        sourceConnectionIds.setActiveLimit(peerTransportParams.getActiveConnectionIdLimit());

        if (processedRetryPacket) {
            if (transportParameters.getOriginalConnectionId() == null ||
                    ! Arrays.equals(destConnectionIds.getOriginalConnectionId(), transportParameters.getOriginalConnectionId())) {
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

    /**
     * Abort connection due to a fatal error in this client. No message is sent to peer; just inform client it's all over.
     * @param error  the exception that caused the trouble
     */
    void abortConnection(Throwable error) {
        if (error != null) {
            if (connectionState == Status.Handshaking) {
                connectionState = Status.HandshakeError;
            } else {
                connectionState = Status.Error;
            }
        }
        else {
            connectionState = Status.Closing;
        }

        if (error != null) {
            log.error("Aborting connection because of error", error);
        }
        handshakeFinishedCondition.countDown();
        terminate();
        streamManager.abortAll();
    }

    protected void registerNewDestinationConnectionId(NewConnectionIdFrame frame) {
        boolean addedNew = destConnectionIds.registerNewConnectionId(frame.getSequenceNr(), frame.getConnectionId());
        if (! addedNew) {
            // Already retired, notify peer
            retireDestinationConnectionId(frame.getSequenceNr());
        }
        if (frame.getRetirePriorTo() > 0) {
            // TODO:
            // https://tools.ietf.org/html/draft-ietf-quic-transport-25#section-19.15
            // "The Retire Prior To field MUST be less than or equal
            //   to the Sequence Number field.  Receiving a value greater than the
            //   Sequence Number MUST be treated as a connection error of type
            //   FRAME_ENCODING_ERROR."
            List<Integer> retired = destConnectionIds.retireAllBefore(frame.getRetirePriorTo());
            retired.forEach(retiredCid -> retireDestinationConnectionId(retiredCid));
            log.info("Peer requests to retire connection ids; switching to destination connection id ", destConnectionIds.getCurrent());
        }
    }

    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-5.1.2
    // "An endpoint can change the connection ID it uses for a peer to
    //   another available one at any time during the connection. "
    public byte[] nextDestinationConnectionId() {
        byte[] newConnectionId = destConnectionIds.useNext();
        log.debug("Switching to next destination connection id: " + ByteUtils.bytesToHex(newConnectionId));
        return newConnectionId;
    }

    public byte[][] newConnectionIds(int count, int retirePriorTo) {
        QuicPacket packet = createPacket(App, null);
        byte[][] newConnectionIds = new byte[count][];

        for (int i = 0; i < count; i++) {
            ConnectionIdInfo cid = sourceConnectionIds.generateNew();
            newConnectionIds[i] = cid.getConnectionId();
            log.debug("New generated source connection id", cid.getConnectionId());
            packet.addFrame(new NewConnectionIdFrame(quicVersion, cid.getSequenceNumber(), retirePriorTo, cid.getConnectionId()));
        }

        send(packet, "new connection id's");
        return newConnectionIds;
    }

    public void retireDestinationConnectionId(Integer sequenceNumber) {
        send(new RetireConnectionIdFrame(quicVersion, sequenceNumber), lostFrame -> retireDestinationConnectionId(sequenceNumber));
        destConnectionIds.retireConnectionId(sequenceNumber);
    }

    // https://tools.ietf.org/html/draft-ietf-quic-transport-22#section-19.16
    // "An endpoint sends a RETIRE_CONNECTION_ID frame (type=0x19) to
    //   indicate that it will no longer use a connection ID that was issued
    //   by its peer."
    private void retireSourceConnectionId(RetireConnectionIdFrame frame) {
        int sequenceNr = frame.getSequenceNr();
        // TODO:
        // https://tools.ietf.org/html/draft-ietf-quic-transport-25#section-19.16
        // "Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number
        //   greater than any previously sent to the peer MUST be treated as a
        //   connection error of type PROTOCOL_VIOLATION."
        sourceConnectionIds.retireConnectionId(sequenceNr);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-25#section-5.1.1
        // "An endpoint SHOULD supply a new connection ID when the peer retires a
        //   connection ID."
        if (! sourceConnectionIds.limitReached()) {
            newConnectionIds(1, 0);
        }
        else {
            log.debug("active connection id limit reached for peer, not sending new");
        }
    }

    public Statistics getStats() {
        return sender.getStats();
    }


    public byte[] getSourceConnectionId() {
        return sourceConnectionIds.getCurrent();
    }

    public Map<Integer, ConnectionIdInfo> getSourceConnectionIds() {
        return sourceConnectionIds.getAll();
    }

    public byte[] getDestinationConnectionId() {
        return destConnectionIds.getCurrent();
    }

    public Map<Integer, ConnectionIdInfo> getDestinationConnectionIds() {
        return destConnectionIds.getAll();
    }

    public void setServerStreamCallback(Consumer<QuicStream> streamProcessor) {
        streamManager.setServerStreamCallback(streamProcessor);
    }

    // For internal use only.
    public long getInitialMaxStreamData() {
        return transportParams.getInitialMaxStreamDataBidiLocal();
    }

    public void setMaxAllowedBidirectionalStreams(int max) {
        transportParams.setInitialMaxStreamsBidi(max);
    }

    public void setMaxAllowedUnidirectionalStreams(int max) {
        transportParams.setInitialMaxStreamsUni(max);
    }

    public void setDefaultStreamReceiveBufferSize(long size) {
        transportParams.setInitialMaxStreamData(size);
    }

    public FlowControl getFlowController() {
        return flowController;
    }

    public void addNewSessionTicket(NewSessionTicket sessionTicket) {
        newSessionTickets.add(sessionTicket);
    }

    public List<NewSessionTicket> getNewSessionTickets() {
        return newSessionTickets;
    }

}
