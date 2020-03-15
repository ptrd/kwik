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
import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.crypto.Keys;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.*;
import net.luminis.quic.recovery.RecoveryManager;
import net.luminis.quic.send.SenderImpl;
import net.luminis.quic.stream.EarlyDataStream;
import net.luminis.quic.stream.FlowControl;
import net.luminis.quic.stream.QuicStream;
import net.luminis.quic.stream.StreamManager;
import net.luminis.tls.*;
import net.luminis.tls.extension.Extension;

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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static net.luminis.quic.EarlyDataStatus.*;
import static net.luminis.quic.EncryptionLevel.*;
import static net.luminis.tls.ByteUtils.bytesToHex;
import static net.luminis.tls.Tls13.generateKeys;


/**
 * Creates and maintains a QUIC connection with a QUIC server.
 */
public class QuicConnectionImpl implements QuicConnection, PacketProcessor, FrameProcessorRegistry<AckFrame> {

    private final List<TlsConstants.CipherSuite> cipherSuites;

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
    private final QuicSessionTicket sessionTicket;
    private final TlsState tlsState;
    private final DatagramSocket socket;
    private final InetAddress serverAddress;
    private final SenderImpl sender;
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
    private HandshakeState handshakeState = HandshakeState.Initial;
    private List<HandshakeStateListener> handshakeStateListeners = new CopyOnWriteArrayList<>();
    private DestinationConnectionIdRegistry destConnectionIds;
    private SourceConnectionIdRegistry sourceConnectionIds;
    private KeepAliveActor keepAliveActor;
    private String applicationProtocol;
    private long flowControlMax;
    private long flowControlLastAdvertised;
    private long flowControlIncrement;
    private long largestPacketNumber;
    private IdleTimer idleTimer;
    private final List<QuicSessionTicket> newSessionTickets = Collections.synchronizedList(new ArrayList<>());
    private boolean ignoreVersionNegotiation;
    private volatile EarlyDataStatus earlyDataStatus = None;
    private List<FrameProcessor2<AckFrame>> ackProcessors = new CopyOnWriteArrayList<>();
    private final GlobalAckGenerator ackGenerator;
    private final List<Runnable> postProcessingActions = new ArrayList<>();


    private QuicConnectionImpl(String host, int port, QuicSessionTicket sessionTicket, Version quicVersion, Logger log, String proxyHost, Path secretsFile, Integer initialRtt, Integer cidLength, List<TlsConstants.CipherSuite> cipherSuites) throws UnknownHostException, SocketException {
        log.info("Creating connection with " + host + ":" + port + " with " + quicVersion);
        this.host = host;
        this.port = port;
        serverAddress = InetAddress.getByName(proxyHost != null? proxyHost: host);
        this.sessionTicket = sessionTicket;
        this.quicVersion = quicVersion;
        this.log = log;
        this.cipherSuites = cipherSuites;

        socket = new DatagramSocket();
        sender = new SenderImpl(quicVersion, getMaxPacketSize(), socket, new InetSocketAddress(serverAddress, port),
                        this, initialRtt, log);
        ackGenerator = sender.getGlobalAckGenerator();
        registerProcessor(ackGenerator);

        receiver = new Receiver(this, socket, 1500, log);
        streamManager = new StreamManager(this, log);
        tlsState = sessionTicket == null? new QuicTlsState(quicVersion): new QuicTlsState(quicVersion, sessionTicket);
        connectionSecrets = new ConnectionSecrets(quicVersion, secretsFile, log);
        sourceConnectionIds = new SourceConnectionIdRegistry(cidLength, log);
        destConnectionIds = new DestinationConnectionIdRegistry(log);
        transportParams = new TransportParameters(60, 250_000, 3 , 3);
        flowControlMax = transportParams.getInitialMaxData();
        flowControlLastAdvertised = flowControlMax;
        flowControlIncrement = flowControlMax / 10;

        idleTimer = new IdleTimer(this, sender::getPto, log);

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
        connect(connectionTimeout, alpn, transportParameters, null);
    }

   /**
     * Set up the connection with the server, enabling use of 0-RTT data.
     * The early data is sent on a bidirectional stream and is assumed to be complete (i.e. the output stream is closed
     * after sending the data).
     * @param connectionTimeout
     * @param earlyData
     * @return
     * @throws IOException
     */
    public synchronized List<QuicStream> connect(int connectionTimeout, String applicationProtocol, TransportParameters transportParameters, List<StreamEarlyData> earlyData) throws IOException {
        this.applicationProtocol = applicationProtocol;
        if (transportParameters != null) {
            this.transportParams = transportParameters;
        }
        this.transportParams.setInitialSourceConnectionId(sourceConnectionIds.getCurrent());
        if (earlyData == null) {
            earlyData = Collections.emptyList();
        }

        log.info(String.format("Original destination connection id: %s (scid: %s)", bytesToHex(destConnectionIds.getCurrent()), bytesToHex(sourceConnectionIds.getCurrent())));
        generateInitialKeys();

        receiver.start();
        sender.start(connectionSecrets);
        startReceiverLoop();

        startHandshake(applicationProtocol, !earlyData.isEmpty());

        List<QuicStream> earlyDataStreams = sendEarlyData(earlyData);

        try {
            boolean handshakeFinished = handshakeFinishedCondition.await(connectionTimeout, TimeUnit.MILLISECONDS);
            if (!handshakeFinished) {
                terminate();
                throw new ConnectException("Connection timed out after " + connectionTimeout + " ms");
            }
            else if (connectionState != Status.Connected) {
                terminate();
                throw new ConnectException("Handshake error");
            }
        }
        catch (InterruptedException e) {
            terminate();
            throw new RuntimeException();  // Should not happen.
        }

        if (!earlyData.isEmpty()) {
            if (earlyDataStatus != Accepted) {
                log.info("Server did not accept early data; retransmitting all data.");
            }
            for (QuicStream stream: earlyDataStreams) {
                if (stream != null) {
                    ((EarlyDataStream) stream).writeRemaining(earlyDataStatus == Accepted);
                }
            }
        }
        return earlyDataStreams;
    }

    private List<QuicStream> sendEarlyData(List<StreamEarlyData> streamEarlyDataList) throws IOException {
        if (!streamEarlyDataList.isEmpty()) {
            TransportParameters rememberedTransportParameters = new TransportParameters();
            sessionTicket.copyTo(rememberedTransportParameters);
            setPeerTransportParameters(rememberedTransportParameters, false);  // Do not validate TP, as these are yet incomplete.
            // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-4.5
            // "the amount of data which the client can send in 0-RTT is controlled by the "initial_max_data"
            //   transport parameter supplied by the server"
            long earlyDataSizeLeft = sessionTicket.getInitialMaxData();

            List<QuicStream> earlyDataStreams = new ArrayList<>();
            for (StreamEarlyData streamEarlyData: streamEarlyDataList) {
                EarlyDataStream earlyDataStream = streamManager.createEarlyDataStream(true);
                if (earlyDataStream != null) {
                    earlyDataStream.writeEarlyData(streamEarlyData.data, streamEarlyData.closeOutput, earlyDataSizeLeft);
                    earlyDataSizeLeft = Long.max(0, earlyDataSizeLeft - streamEarlyData.data.length);
                }
                else {
                    log.info("Creating early data stream failed, max bidi streams = " + rememberedTransportParameters.getInitialMaxStreamsBidi());
                }
                earlyDataStreams.add(earlyDataStream);
            }
            earlyDataStatus = Requested;
            return earlyDataStreams;
        }
        else {
            return Collections.emptyList();
        }
    }

    public void keepAlive(int seconds) {
        if (connectionState != Status.Connected) {
            throw new IllegalStateException("keep alive can only be set when connected");
        }

        keepAliveActor = new KeepAliveActor(quicVersion, seconds, (int) peerTransportParams.getMaxIdleTimeout(), sender);
    }

    public void ping() {
        if (connectionState == Status.Connected) {
            sender.send(new PingFrame(quicVersion), App);
            sender.flush();
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
                    sender.datagramProcessed(receiver.hasMore());
                }
            }
        }
        catch (InterruptedException e) {
            log.debug("Terminating receiver loop because of interrupt");
        }
        catch (Exception error) {
            log.error("Terminating receiver loop because of error", error);
            abortConnection(error);
        }
    }

    private void generateInitialKeys() {
        connectionSecrets.computeInitialKeys(destConnectionIds.getCurrent());
    }

    private void startHandshake(String applicationProtocol, boolean withEarlyData) {
        byte[] clientHello = createClientHello(host, cipherSuites, publicKey, applicationProtocol, withEarlyData);
        tlsState.clientHelloSend(privateKey, clientHello);
        connectionSecrets.computeEarlySecrets(tlsState);

        CryptoFrame clientHelloFrame = new CryptoFrame(quicVersion, clientHello);
        connectionState = Status.Handshaking;
        sender.sendInitial(clientHelloFrame, token);
    }

    public void hasHandshakeKeys() {
        synchronized (handshakeState) {
            if (handshakeState.transitionAllowed(HandshakeState.HasHandshakeKeys)) {
                handshakeState = HandshakeState.HasHandshakeKeys;
                handshakeStateListeners.forEach(l -> l.handshakeStateChangedEvent(handshakeState));
            }
            else {
                log.debug("Handshake state cannot be set to HasHandshakeKeys");
            }
        }

        // https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-4.11.1
        // "Thus, a client MUST discard Initial keys when it first sends a Handshake packet (...). This results in
        //  abandoning loss recovery state for the Initial encryption level and ignoring any outstanding Initial packets."
        // This is done as post-processing action to ensure ack on Initial level is sent.
        postProcessingActions.add(() -> {
            log.recovery("Discarding pn-space Initial, because first Handshake message is being sent");
            discard(PnSpace.Initial);
        });
    }

    private void discard(PnSpace pnSpace) {
        sender.discard(pnSpace);
    }

    void finishHandshake(TlsState tlsState) {
        if (tlsState.isServerFinished()) {
            FinishedMessage finishedMessage = new FinishedMessage(tlsState);
            CryptoFrame cryptoFrame = new CryptoFrame(quicVersion, finishedMessage.getBytes());
            sendClientFinished(cryptoFrame);
            tlsState.computeApplicationSecrets();
            connectionSecrets.computeApplicationSecrets(tlsState);
            synchronized (handshakeState) {
                if (handshakeState.transitionAllowed(HandshakeState.HasAppKeys)) {
                    handshakeState = HandshakeState.HasAppKeys;
                    handshakeStateListeners.forEach(l -> l.handshakeStateChangedEvent(handshakeState));
                } else {
                    log.debug("Handshake state cannot be set to HasAppKeys");
                }
            }

            connectionState = Status.Connected;
            handshakeFinishedCondition.countDown();
        }
    }

    void sendClientFinished(QuicFrame cryptoFrame) {
        sender.send(cryptoFrame, Handshake, frameToRetransmit -> {
            log.recovery("Retransmitting client finished.");
            sender.send(frameToRetransmit, Handshake, this::sendClientFinished);
        });
    }

    void parsePackets(int datagram, Instant timeReceived, ByteBuffer data) {
        while (data.remaining() > 0) {
            try {
                QuicPacket packet = parsePacket(data);

                log.received(timeReceived, datagram, packet);
                log.debug("Parsed packet with size " + data.position() + "; " + data.remaining() + " bytes left.");

                processPacket(timeReceived, packet);
                sender.packetProcessed(data.hasRemaining());
            }
            catch (DecryptionException | MissingKeysException cannotParse) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-12.2
                // "if decryption fails (...), the receiver (...) MUST attempt to process the remaining packets."
                log.error("Discarding packet (" + data.position() + " bytes) that cannot be decrypted (" + cannotParse + ")");
            }
            catch (InvalidPacketException invalidPacket) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-5.2
                // "Invalid packets without packet protection, such as Initial, Retry, or Version Negotiation, MAY be discarded."
                log.debug("Dropping invalid packet");
            }

            if (data.position() == 0) {
                // If parsing (or an attempt to parse a) packet does not advance the buffer, there is no point in going on.
                break;
            }

            // Make sure the packet starts at the beginning of the buffer (required by parse routines)
            data = data.slice();
        }

        // Processed all packets in the datagram.
        sender.packetProcessed(false);

        // Finally, execute actions that need to be executed after all responses and acks are sent.
        postProcessingActions.forEach(action -> action.run());
        postProcessingActions.clear();
    }

    QuicPacket parsePacket(ByteBuffer data) throws MissingKeysException, DecryptionException, InvalidPacketException {
        data.mark();
        if (data.remaining() < 2) {
            throw new InvalidPacketException("packet too short to be valid QUIC packet");
        }
        int flags = data.get();

        if ((flags & 0x40) != 0x40) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-17.2
            // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-17.3
            // "Fixed Bit:  The next bit (0x40) of byte 0 is set to 1.  Packets
            //      containing a zero value for this bit are not valid packets in this
            //      version and MUST be discarded."
            throw new InvalidPacketException();
        }

        QuicPacket packet;
        if ((flags & 0x80) == 0x80) {
            // Long header packet
            packet = createLongHeaderPacket(flags, data);
        }
        else {
            // Short header packet
            packet = new ShortHeaderPacket(quicVersion);
        }
        data.rewind();

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

    /**
     * Constructs a (yet empty) long header packet based on the packet flags (first byte).
     * @param flags   first byte of data to parse
     * @param data    data to parse, first byte is already read!
     * @return
     * @throws InvalidPacketException
     */
    private QuicPacket createLongHeaderPacket(int flags, ByteBuffer data) throws InvalidPacketException {
        final int MIN_LONGHEADERPACKET_LENGTH = 1 + 4 + 1 + 0 + 1 + 0;
        if (1 + data.remaining() < MIN_LONGHEADERPACKET_LENGTH) {
            throw new InvalidPacketException("packet too short to be valid QUIC long header packet");
        }
        int version = data.getInt();

        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.4:
        // "A Version Negotiation packet ... will appear to be a packet using the long header, but
        //  will be identified as a Version Negotiation packet based on the
        //  Version field having a value of 0."
        if (version == 0) {
            return new VersionNegotiationPacket(quicVersion);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.5
        // "An Initial packet uses long headers with a type value of 0x0."
        else if ((flags & 0xf0) == 0xc0) {  // 1100 0000
            return new InitialPacket(quicVersion);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.7
        // "A Retry packet uses a long packet header with a type value of 0x3"
        else if ((flags & 0xf0) == 0xf0) {  // 1111 0000
            // Retry packet....
            return new RetryPacket(quicVersion);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.6
        // "A Handshake packet uses long headers with a type value of 0x2."
        else if ((flags & 0xf0) == 0xe0) {  // 1110 0000
            return new HandshakePacket(quicVersion);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.2
        // "|  0x1 | 0-RTT Protected | Section 12.1 |"
        else if ((flags & 0xf0) == 0xd0) {  // 1101 0000
            // 0-RTT Protected
            // "It is used to carry "early"
            //   data from the client to the server as part of the first flight, prior
            //   to handshake completion."
            // As this library is client-only, this cannot happen.
            // When such a packet arrives, consider it to be caused by network corruption, so
            throw new InvalidPacketException();
        }
        else {
            // Should not happen, all cases should be covered above, but just in case...
            throw new RuntimeException();
        }
    }

    private void processPacket(Instant timeReceived, QuicPacket packet) {
        packet.accept(this, timeReceived);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-13.1
        // "A packet MUST NOT be acknowledged until packet protection has been
        //   successfully removed and all frames contained in the packet have been
        //   processed."
        ackGenerator.packetReceived(packet);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
        // "An endpoint restarts its idle timer when a packet from its peer is received and processed successfully."
        idleTimer.packetProcessed();
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

    private byte[] createClientHello(String host, List<TlsConstants.CipherSuite> supportedCiphers, ECPublicKey publicKey, String alpnProtocol, boolean useEarlyData) {
        boolean compatibilityMode = false;

        List<Extension> quicExtensions = new ArrayList<>();
        quicExtensions.add(new QuicTransportParametersExtension(quicVersion, transportParams));
        quicExtensions.add(new ApplicationLayerProtocolNegotiationExtension(alpnProtocol));
        if (useEarlyData) {
            quicExtensions.add(new EarlyDataExtension());
        }

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
        ignoreVersionNegotiation = true;
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
    public void process(VersionNegotiationPacket vnPacket, Instant time) {
        if (!ignoreVersionNegotiation && !vnPacket.getServerSupportedVersions().contains(quicVersion)) {
            log.info("Server doesn't support " + quicVersion + ", but only: " + ((VersionNegotiationPacket) vnPacket).getServerSupportedVersions().stream().map(v -> v.toString()).collect(Collectors.joining(", ")));
            throw new VersionNegotiationFailure();
        }
        else {
            // Must be a corrupted packet or sent because of a corrupted packet, so ignore.
            log.debug("Ignoring Version Negotiation packet");
        }
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
                destConnectionIds.setRetrySourceConnectionId(destConnectionId);
                log.debug("Changing destination connection id into: " + bytesToHex(destConnectionId));
                generateInitialKeys();

                // https://tools.ietf.org/html/draft-ietf-quic-recovery-18#section-6.2.1.1
                // "A Retry or Version Negotiation packet causes a client to send another
                //   Initial packet, effectively restarting the connection process and
                //   resetting congestion control..."
                sender.getCongestionController().reset();

                startHandshake(applicationProtocol, false);
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
                ackProcessors.forEach(p -> p.process((AckFrame) frame, packet.getPnSpace(), timeReceived));
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
                log.recovery("Discarding pn space Handshake because HandshakeDone is received");
                sender.discard(PnSpace.Handshake);
                synchronized (handshakeState) {
                    if (handshakeState.transitionAllowed(HandshakeState.Confirmed)) {
                        handshakeState = HandshakeState.Confirmed;
                        handshakeStateListeners.forEach(l -> l.handshakeStateChangedEvent(handshakeState));
                    } else {
                        log.debug("Handshake state cannot be set to Confirmed");
                    }
                }
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
        sender.flush();

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
        idleTimer.shutdown();
        sender.shutdown();
        receiver.shutdown();
        socket.close();
    }

    public void send(QuicFrame frame, Consumer<QuicFrame> lostFrameCallback) {
        send(frame, lostFrameCallback, false);
    }

    public void send(QuicFrame frame, Consumer<QuicFrame> lostFrameCallback, boolean flush) {
        sender.send(frame, App, lostFrameCallback);
        if (flush) {
            sender.flush();
        }
    }

    public void sendZeroRtt(QuicFrame frame, Consumer<QuicFrame> lostFrameCallback) {
        sender.send(frame, ZeroRTT, lostFrameCallback);
    }

    private void retransmitAppData(QuicFrame frame) {
        sender.send(frame, App, this::retransmitAppData);
    }

    public void updateConnectionFlowControl(int size) {
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
        setPeerTransportParameters(transportParameters, true);
    }

    private void setPeerTransportParameters(TransportParameters transportParameters, boolean validate) {
        if (validate) {
            if (!verifyConnectionIds(transportParameters)) {
                return;
            }
        }
        peerTransportParams = transportParameters;
        if (flowController == null) {
            flowController = new FlowControl(peerTransportParams.getInitialMaxData(),
                    peerTransportParams.getInitialMaxStreamDataBidiLocal(),
                    peerTransportParams.getInitialMaxStreamDataBidiRemote(),
                    peerTransportParams.getInitialMaxStreamDataUni(),
                    log);
            streamManager.setFlowController(flowController);
        }
        else {
            // If the client has sent 0-rtt, the flow controller will already have been initialized with "remembered" values
            log.debug("Updating flow controller with new transport parameters");
            // TODO: this should be postponed until all 0-rtt packets are sent
            flowController.updateInitialValues(peerTransportParams);
        }

        streamManager.setInitialMaxStreamsBidi(peerTransportParams.getInitialMaxStreamsBidi());
        streamManager.setInitialMaxStreamsUni(peerTransportParams.getInitialMaxStreamsUni());

        sender.setReceiverMaxAckDelay(peerTransportParams.getMaxAckDelay());
        sourceConnectionIds.setActiveLimit(peerTransportParams.getActiveConnectionIdLimit());

        // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
        // "If a max_idle_timeout is specified by either peer in its transport parameters (Section 18.2), the
        //  connection is silently closed and its state is discarded when it remains idle for longer than the minimum
        //  of both peers max_idle_timeout values."
        long idleTimeout = Long.min(transportParams.getMaxIdleTimeout(), peerTransportParams.getMaxIdleTimeout());
        if (idleTimeout == 0) {
            idleTimeout = Long.max(transportParams.getMaxIdleTimeout(), peerTransportParams.getMaxIdleTimeout());
        }
        if (idleTimeout != 0) {
            log.info("Effective idle timeout is " + idleTimeout);
            // Initialise the idle timer that will take care of (silently) closing connection if idle longer than idle timeout
            idleTimer.setIdleTimeout(idleTimeout);
        }
        else {
            // Both or 0 or not set:
            // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-18.2
            // "Idle timeout is disabled when both endpoints omit this transport parameter or specify a value of 0."
        }

        if (processedRetryPacket) {
            if (peerTransportParams.getRetrySourceConnectionId() == null ||
                    ! Arrays.equals(destConnectionIds.getRetrySourceConnectionId(), peerTransportParams.getRetrySourceConnectionId())) {
                signalConnectionError(QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR);
            }
        }
        else {
            if (peerTransportParams.getRetrySourceConnectionId() != null) {
                signalConnectionError(QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR);
            }
        }
    }

    private boolean verifyConnectionIds(TransportParameters transportParameters) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-7.3
        // "An endpoint MUST treat absence of the initial_source_connection_id
        //   transport parameter from either endpoint or absence of the
        //   original_destination_connection_id transport parameter from the
        //   server as a connection error of type TRANSPORT_PARAMETER_ERROR."
        if (transportParameters.getInitialSourceConnectionId() == null || transportParameters.getOriginalDestinationConnectionId() == null) {
            log.error("Missing connection id from server transport parameter");
            signalConnectionError(QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR);
            return false;
        }

        // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-7.3
        // "An endpoint MUST treat the following as a connection error of type TRANSPORT_PARAMETER_ERROR or PROTOCOL_VIOLATION:
        //   *  a mismatch between values received from a peer in these transport parameters and the value sent in the
        //      corresponding Destination or Source Connection ID fields of Initial packets."
        if (! Arrays.equals(destConnectionIds.getCurrent(), transportParameters.getInitialSourceConnectionId())) {
            log.error("Source connection id does not match corresponding transport parameter");
            signalConnectionError(QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION);
            return false;
        }
        if (! Arrays.equals(destConnectionIds.getOriginalConnectionId(), transportParameters.getOriginalDestinationConnectionId())) {
            log.error("Original destination connection id does not match corresponding transport parameter");
            signalConnectionError(QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION);
            return false;
        }

        return true;
    }

    void signalConnectionError(QuicConstants.TransportErrorCode transportError) {
        log.info("ConnectionError " + transportError);
        // TODO: close connection with a frame type of 0x1c
        abortConnection(null);
    }

    /**
     * Abort connection due to a fatal error in this client. No message is sent to peer; just inform client it's all over.
     * @param error  the exception that caused the trouble
     */
    public void abortConnection(Throwable error) {
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

    void silentlyCloseConnection(long idleTime) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-10.2
        // "If the idle timeout is enabled by either peer, a connection is
        //   silently closed and its state is discarded when it remains idle for
        //   longer than the minimum of the max_idle_timeouts (see Section 18.2)
        //   and three times the current Probe Timeout (PTO)."
        log.info("Idle timeout: silently closing connection after " + idleTime + " ms of inactivity (" + bytesToHex(sourceConnectionIds.getCurrent()) + ")");
        abortConnection(null);
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
        log.debug("Switching to next destination connection id: " + bytesToHex(newConnectionId));
        return newConnectionId;
    }

    public byte[][] newConnectionIds(int count, int retirePriorTo) {
        byte[][] newConnectionIds = new byte[count][];

        for (int i = 0; i < count; i++) {
            ConnectionIdInfo cid = sourceConnectionIds.generateNew();
            newConnectionIds[i] = cid.getConnectionId();
            log.debug("New generated source connection id", cid.getConnectionId());
            sender.send(new NewConnectionIdFrame(quicVersion, cid.getSequenceNumber(), retirePriorTo, cid.getConnectionId()), App);
        }
        sender.flush();
        
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
        return new Statistics(sender.getStatistics());
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

    public void addNewSessionTicket(NewSessionTicket tlsSessionTicket) {
       if (tlsSessionTicket.hasEarlyDataExtension()) {
            if (tlsSessionTicket.getEarlyDataMaxSize() != 0xffffffffL) {
                // https://tools.ietf.org/html/draft-ietf-quic-tls-24#section-4.5
                // "Servers MUST NOT send
                //   the "early_data" extension with a max_early_data_size set to any
                //   value other than 0xffffffff.  A client MUST treat receipt of a
                //   NewSessionTicket that contains an "early_data" extension with any
                //   other value as a connection error of type PROTOCOL_VIOLATION."
                log.error("Invalid quic new session ticket (invalid early data size); ignoring ticket.");
            }
        }
        newSessionTickets.add(new QuicSessionTicket(tlsSessionTicket, peerTransportParams));
    }

    public List<QuicSessionTicket> getNewSessionTickets() {
        return newSessionTickets;
    }

    public EarlyDataStatus getEarlyDataStatus() {
        return earlyDataStatus;
    }

    public void setEarlyDataStatus(EarlyDataStatus earlyDataStatus) {
        this.earlyDataStatus = earlyDataStatus;
    }

    public void addHandshakeStateListener(RecoveryManager recoveryManager) {
        handshakeStateListeners.add(recoveryManager);
    }

    public URI getUri() {
        try {
            return new URI("//" + host + ":" + port);
        } catch (URISyntaxException e) {
            // Impossible
            throw new IllegalStateException();
        }
    }

    public void registerProcessor(FrameProcessor2<AckFrame> ackProcessor) {
        ackProcessors.add(ackProcessor);
    }

    public InetSocketAddress getLocalAddress() {
        return (InetSocketAddress) socket.getLocalSocketAddress();
    }


    public static Builder newBuilder() {
        return new BuilderImpl();
    }

    public interface Builder {
        QuicConnectionImpl build() throws SocketException, UnknownHostException;

        Builder connectTimeout(Duration duration);

        Builder version(Version version);

        Builder logger(Logger log);

        Builder sessionTicket(QuicSessionTicket ticket);

        Builder proxy(String host);

        Builder secrets(Path secretsFile);

        Builder uri(URI uri);

        Builder connectionIdLength(int length);

        Builder initialRtt(int initialRtt);

        Builder cipherSuite(TlsConstants.CipherSuite cipherSuite);
    }

    private static class BuilderImpl implements Builder {
        private String host;
        private int port;
        private QuicSessionTicket sessionTicket;
        private Version quicVersion = Version.getDefault();
        private Logger log;
        private String proxyHost;
        private Path secretsFile;
        private Integer initialRtt;
        private Integer connectionIdLength;
        private List<TlsConstants.CipherSuite> cipherSuites = new ArrayList<>();

        @Override
        public QuicConnectionImpl build() throws SocketException, UnknownHostException {
            if (! quicVersion.atLeast(Version.IETF_draft_23)) {
                throw new IllegalArgumentException("Quic version " + quicVersion + " not supported");
            }
            if (host == null) {
                throw new IllegalStateException("Cannot create connection when URI is not set");
            }
            if (initialRtt != null && initialRtt < 1) {
                throw new IllegalArgumentException("Initial RTT must be larger than 0.");
            }
            if (cipherSuites.isEmpty()) {
                cipherSuites.add(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);
            }
            return new QuicConnectionImpl(host, port, sessionTicket, quicVersion, log, proxyHost, secretsFile, initialRtt, connectionIdLength, cipherSuites);
        }

        @Override
        public Builder connectTimeout(Duration duration) {
            return this;
        }

        @Override
        public Builder version(Version version) {
            quicVersion = version;
            return this;
        }

        @Override
        public Builder logger(Logger log) {
            this.log = log;
            return this;
        }

        @Override
        public Builder sessionTicket(QuicSessionTicket ticket) {
            sessionTicket = ticket;
            return this;
        }

        @Override
        public Builder proxy(String host) {
            proxyHost = host;
            return this;
        }

        @Override
        public Builder secrets(Path secretsFile) {
            this.secretsFile = secretsFile;
            return this;
        }

        @Override
        public Builder uri(URI uri) {
            host = uri.getHost();
            port = uri.getPort();
            return this;
        }

        @Override
        public Builder connectionIdLength(int length) {
            if (length < 0 || length > 20) {
                throw new IllegalArgumentException("Connection ID length must between 0 and 20.");
            }
            connectionIdLength = length;
            return this;
        }

        @Override
        public Builder initialRtt(int initialRtt) {
            this.initialRtt = initialRtt;
            return this;
        }

        @Override
        public Builder cipherSuite(TlsConstants.CipherSuite cipherSuite) {
            cipherSuites.add(cipherSuite);
            return this;
        }
    }

    public IdleTimer getIdleTimer() {
        return idleTimer;
    }

}
