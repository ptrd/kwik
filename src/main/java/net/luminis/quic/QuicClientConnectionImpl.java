/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic;

import net.luminis.quic.cid.ConnectionIdInfo;
import net.luminis.quic.cid.ConnectionIdManager;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.NullLogger;
import net.luminis.quic.packet.*;
import net.luminis.quic.send.SenderImpl;
import net.luminis.quic.stream.EarlyDataStream;
import net.luminis.quic.stream.FlowControl;
import net.luminis.quic.stream.StreamManager;
import net.luminis.quic.tls.QuicTransportParametersExtension;
import net.luminis.tls.*;
import net.luminis.tls.extension.ApplicationLayerProtocolNegotiationExtension;
import net.luminis.tls.extension.EarlyDataExtension;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.handshake.*;

import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static net.luminis.quic.EarlyDataStatus.*;
import static net.luminis.quic.EncryptionLevel.*;
import static net.luminis.quic.QuicConstants.TransportErrorCode.*;
import static net.luminis.tls.util.ByteUtils.bytesToHex;


/**
 * Creates and maintains a QUIC connection with a QUIC server.
 */
public class QuicClientConnectionImpl extends QuicConnectionImpl implements QuicClientConnection, PacketProcessor, FrameProcessorRegistry<AckFrame>, TlsStatusEventHandler, FrameProcessor3 {

    private final String host;
    private final int port;
    private final QuicSessionTicket sessionTicket;
    private final TlsClientEngine tlsEngine;
    private final DatagramSocket socket;
    private final InetAddress serverAddress;
    private final SenderImpl sender;
    private final Receiver receiver;
    private final StreamManager streamManager;
    private final X509Certificate clientCertificate;
    private final PrivateKey clientCertificateKey;
    private final ConnectionIdManager connectionIdManager;
    private final Version originalVersion;
    private final Version preferredVersion;
    private volatile byte[] token;
    private final CountDownLatch handshakeFinishedCondition = new CountDownLatch(1);
    private volatile TransportParameters peerTransportParams;
    private KeepAliveActor keepAliveActor;
    private String applicationProtocol;
    private final List<QuicSessionTicket> newSessionTickets = Collections.synchronizedList(new ArrayList<>());
    private boolean ignoreVersionNegotiation;
    private volatile EarlyDataStatus earlyDataStatus = None;
    private List<FrameProcessor2<AckFrame>> ackProcessors = new CopyOnWriteArrayList<>();
    private final List<TlsConstants.CipherSuite> cipherSuites;

    private final GlobalAckGenerator ackGenerator;
    private Integer clientHelloEnlargement;
    private volatile Thread receiverThread;


    private QuicClientConnectionImpl(String host, int port, QuicSessionTicket sessionTicket, Version originalVersion, Version preferredVersion, Logger log,
                                     String proxyHost, Path secretsFile, Integer initialRtt, Integer cidLength,
                                     List<TlsConstants.CipherSuite> cipherSuites,
                                     X509Certificate clientCertificate, PrivateKey clientCertificateKey) throws UnknownHostException, SocketException {
        super(originalVersion, Role.Client, secretsFile, log);
        log.info("Creating connection with " + host + ":" + port + " with " + originalVersion);
        this.originalVersion = originalVersion;
        this.preferredVersion = preferredVersion;
        this.host = host;
        this.port = port;
        serverAddress = InetAddress.getByName(proxyHost != null? proxyHost: host);
        this.sessionTicket = sessionTicket;
        this.cipherSuites = cipherSuites;
        this.clientCertificate = clientCertificate;
        this.clientCertificateKey = clientCertificateKey;

        socket = new DatagramSocket();

        idleTimer = new IdleTimer(this, log);
        sender = new SenderImpl(quicVersion, getMaxPacketSize(), socket, new InetSocketAddress(serverAddress, port),
                        this, initialRtt, log);
        sender.enableAllLevels();
        idleTimer.setPtoSupplier(sender::getPto);
        ackGenerator = sender.getGlobalAckGenerator();
        registerProcessor(ackGenerator);

        receiver = new Receiver(socket, log, this::abortConnection);
        streamManager = new StreamManager(this, Role.Client, log, 10, 10);

        BiConsumer<Integer, String> closeWithErrorFunction = (error, reason) -> {
            immediateCloseWithError(EncryptionLevel.App, error, reason);
        };
        connectionIdManager = new ConnectionIdManager(cidLength, 2, sender, closeWithErrorFunction, log);

        connectionState = Status.Created;
        tlsEngine = new TlsClientEngine(new ClientMessageSender() {
            @Override
            public void send(ClientHello clientHello) {
                CryptoStream cryptoStream = getCryptoStream(Initial);
                cryptoStream.write(clientHello, true);
                connectionState = Status.Handshaking;
                connectionSecrets.setClientRandom(clientHello.getClientRandom());
                log.sentPacketInfo(cryptoStream.toStringSent());
            }

            @Override
            public void send(FinishedMessage finished) {
                CryptoStream cryptoStream = getCryptoStream(Handshake);
                cryptoStream.write(finished, true);
                log.sentPacketInfo(cryptoStream.toStringSent());
            }

            @Override
            public void send(CertificateMessage certificateMessage) throws IOException {
                CryptoStream cryptoStream = getCryptoStream(Handshake);
                cryptoStream.write(certificateMessage, true);
                log.sentPacketInfo(cryptoStream.toStringSent());
            }

            @Override
            public void send(CertificateVerifyMessage certificateVerifyMessage) {
                CryptoStream cryptoStream = getCryptoStream(Handshake);
                cryptoStream.write(certificateVerifyMessage, true);
                log.sentPacketInfo(cryptoStream.toStringSent());
            }
        }, this);
    }

    /**
     * Set up the connection with the server.
     */
    @Override
    public void connect(int connectionTimeout, String alpn) throws IOException {
        connect(connectionTimeout, alpn, null, null);
    }

    @Override
    public void connect(int connectionTimeout, String alpn, TransportParameters transportParameters) throws IOException {
        connect(connectionTimeout, alpn, transportParameters, null);
    }

    /**
     * Set up the connection with the server, enabling use of 0-RTT data.
     * The early data is sent on a bidirectional stream and the output stream is closed immediately after sending the data
     * if <code>closeOutput</code> is set in the <code>StreamEarlyData</code>.
     * If this connection object is not in the initial state, an <code>IllegalStateException</code> will be thrown, so
     * the connect method can only be successfully called once. Use the <code>isConnected</code> method to check whether
     * it can be connected.
     *
     * @param connectionTimeout  the connection timeout in milliseconds
     * @param applicationProtocol  the ALPN of the protocol that will be used on top of the QUIC connection
     * @param transportParameters  the transport parameters to use for the connection
     * @param earlyData            early data to send (RTT-0), each element of the list will lead to a bidirectional stream
     * @return                     list of streams that was created for the early data; the size of the list will be equal
     * to the size of the list of the <code>earlyData</code> parameter, but may contain <code>null</code>s if a stream
     * could not be created due to reaching the max initial streams limit.
     * @throws IOException
     */
    @Override
    public synchronized List<QuicStream> connect(int connectionTimeout, String applicationProtocol, TransportParameters transportParameters, List<StreamEarlyData> earlyData) throws IOException {
        if (applicationProtocol.trim().isEmpty()) {
            throw new IllegalArgumentException("ALPN cannot be empty");
        }
        if (connectionState != Status.Created) {
            throw new IllegalStateException("Cannot connect a connection that is in state " + connectionState);
        }
        if (earlyData != null && !earlyData.isEmpty() && sessionTicket == null) {
            throw new IllegalStateException("Cannot send early data without session ticket");
        }
        this.applicationProtocol = applicationProtocol;
        if (transportParameters != null) {
            this.transportParams = transportParameters;
            connectionIdManager.setMaxPeerConnectionIds(transportParams.getActiveConnectionIdLimit());
        }
        this.transportParams.setInitialSourceConnectionId(connectionIdManager.getInitialConnectionId());
        if (earlyData == null) {
            earlyData = Collections.emptyList();
        }

        log.info(String.format("Original destination connection id: %s (scid: %s)", bytesToHex(connectionIdManager.getOriginalDestinationConnectionId()), bytesToHex(connectionIdManager.getInitialConnectionId())));
        generateInitialKeys();

        receiver.start();
        sender.start(connectionSecrets);
        startReceiverLoop();

        startHandshake(applicationProtocol, !earlyData.isEmpty());

        List<QuicStream> earlyDataStreams = sendEarlyData(earlyData);

        try {
            boolean handshakeFinished = handshakeFinishedCondition.await(connectionTimeout, TimeUnit.MILLISECONDS);
            if (!handshakeFinished) {
                abortHandshake();
                throw new ConnectException("Connection timed out after " + connectionTimeout + " ms");
            }
            else if (connectionState != Status.Connected) {
                abortHandshake();
                throw new ConnectException("Handshake error");
            }
        }
        catch (InterruptedException e) {
            abortHandshake();
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
            setZeroRttTransportParameters(rememberedTransportParameters);
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

    private void abortHandshake() {
        connectionState = Status.Failed;
        sender.stop();
        terminate();
    }

    @Override
    public void keepAlive(int seconds) {
        if (connectionState != Status.Connected) {
            throw new IllegalStateException("keep alive can only be set when connected");
        }

        if (idleTimer.isEnabled()) {
            keepAliveActor = new KeepAliveActor(quicVersion, seconds, (int) idleTimer.getIdleTimeout(), sender);
        }
    }

    public void ping() {
        if (connectionState == Status.Connected) {
            sender.send(new PingFrame(quicVersion.getVersion()), App);
            sender.flush();
        }
        else {
            throw new IllegalStateException("not connected");
        }
    }

    private void startReceiverLoop() {
        receiverThread = new Thread(this::receiveAndProcessPackets, "receiver-loop");
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

                    parseAndProcessPackets(receivedPacketCounter, rawPacket.getTimeReceived(), rawPacket.getData(), null);
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
        connectionSecrets.computeInitialKeys(connectionIdManager.getCurrentPeerConnectionId());
    }

    private void startHandshake(String applicationProtocol, boolean withEarlyData) {
        tlsEngine.setServerName(host);
        tlsEngine.addSupportedCiphers(cipherSuites);
        if (clientCertificate != null && clientCertificateKey != null) {
            tlsEngine.setClientCertificateCallback(authorities -> {
                if (! authorities.contains(clientCertificate.getIssuerX500Principal())) {
                    log.warn("Client certificate is not signed by one of the requested authorities: " + authorities);
                }
                return new CertificateWithPrivateKey(clientCertificate, clientCertificateKey);
            });
        }

        if (preferredVersion != null && !preferredVersion.equals(originalVersion)) {
            transportParams.setVersionInformation(new TransportParameters.VersionInformation(originalVersion,
                    List.of(preferredVersion, originalVersion)));
        }
        else if (quicVersion.getVersion().isV2()) {
            transportParams.setVersionInformation(new TransportParameters.VersionInformation(Version.QUIC_version_2,
                    List.of(Version.QUIC_version_2, Version.QUIC_version_1)));
        }
        QuicTransportParametersExtension tpExtension = new QuicTransportParametersExtension(quicVersion.getVersion(), transportParams, Role.Client);
        if (clientHelloEnlargement != null) {
            tpExtension.addDiscardTransportParameter(clientHelloEnlargement);
        }
        tlsEngine.add(tpExtension);
        tlsEngine.add(new ApplicationLayerProtocolNegotiationExtension(applicationProtocol));
        if (withEarlyData) {
            tlsEngine.add(new EarlyDataExtension());
        }
        if (sessionTicket != null) {
            tlsEngine.setNewSessionTicket(sessionTicket);
        }

        try {
            tlsEngine.startHandshake();
        } catch (IOException e) {
            // Will not happen, as our ClientMessageSender implementation will not throw.
        }
    }

    @Override
    public void earlySecretsKnown() {
        connectionSecrets.computeEarlySecrets(tlsEngine, quicVersion.getVersion());
    }

    @Override
    public void handshakeSecretsKnown() {
        // Server Hello provides a new secret, so:
        connectionSecrets.computeHandshakeSecrets(tlsEngine, tlsEngine.getSelectedCipher());
        hasHandshakeKeys();
    }

    public void hasHandshakeKeys() {
        synchronized (handshakeStateLock) {
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
            discard(PnSpace.Initial, "first Handshake message is being sent");
        });
    }

    @Override
    public void handshakeFinished() {
            connectionSecrets.computeApplicationSecrets(tlsEngine);
            synchronized (handshakeStateLock) {
                if (handshakeState.transitionAllowed(HandshakeState.HasAppKeys)) {
                    handshakeState = HandshakeState.HasAppKeys;
                    handshakeStateListeners.forEach(l -> l.handshakeStateChangedEvent(handshakeState));
                } else {
                    log.error("Handshake state cannot be set to HasAppKeys; current state is " + handshakeState);
                }
            }

            connectionState = Status.Connected;
            handshakeFinishedCondition.countDown();
    }

    @Override
    public void newSessionTicketReceived(NewSessionTicket ticket) {
        addNewSessionTicket(ticket);
    }

    @Override
    public void extensionsReceived(List<Extension> extensions) {
        extensions.forEach(ex -> {
            if (ex instanceof EarlyDataExtension) {
                setEarlyDataStatus(EarlyDataStatus.Accepted);
                log.info("Server has accepted early data.");
            }
            else if (ex instanceof QuicTransportParametersExtension) {
                setPeerTransportParameters(((QuicTransportParametersExtension) ex).getTransportParameters());
            }
        });
    }

    @Override
    public boolean isEarlyDataAccepted() {
        return false;
    }

    private void discard(PnSpace pnSpace, String reason) {
        sender.discard(pnSpace, reason);
    }

    @Override
    public ProcessResult process(InitialPacket packet, Instant time) {
        if (! packet.getVersion().equals(quicVersion)) {
            handleVersionNegotiation(packet.getVersion());
        }
        connectionIdManager.registerInitialPeerCid(packet.getSourceConnectionId());
        processFrames(packet, time);
        ignoreVersionNegotiation = true;
        return ProcessResult.Continue;
    }

    private void handleVersionNegotiation(Version packetVersion) {
        if (! packetVersion.equals(quicVersion)) {
            if (packetVersion.equals(preferredVersion) && versionNegotiationStatus == VersionNegotiationStatus.NotStarted) {
                versionNegotiationStatus = VersionNegotiationStatus.VersionChangeUnconfirmed;
                quicVersion.setVersion(packetVersion);
                connectionSecrets.recomputeInitialKeys();
            }
        }
    }

    @Override
    public ProcessResult process(HandshakePacket packet, Instant time) {
        processFrames(packet, time);
        return ProcessResult.Continue;
    }

    @Override
    public ProcessResult process(ShortHeaderPacket packet, Instant time) {
        connectionIdManager.registerConnectionIdInUse(packet.getDestinationConnectionId());
        processFrames(packet, time);
        return ProcessResult.Continue;
    }

    @Override
    public ProcessResult process(VersionNegotiationPacket vnPacket, Instant time) {
        if (!ignoreVersionNegotiation && !vnPacket.getServerSupportedVersions().contains(quicVersion.getVersion())) {
            log.info("Server doesn't support " + quicVersion + ", but only: " + ((VersionNegotiationPacket) vnPacket).getServerSupportedVersions().stream().map(v -> v.toString()).collect(Collectors.joining(", ")));
            throw new VersionNegotiationFailure();
        }
        else {
            // Must be a corrupted packet or sent because of a corrupted packet, so ignore.
            log.debug("Ignoring Version Negotiation packet");
        }
        return ProcessResult.Continue;
    }

    private volatile boolean processedRetryPacket = false;

    @Override
    public ProcessResult process(RetryPacket packet, Instant time) {
        if (packet.validateIntegrityTag(connectionIdManager.getOriginalDestinationConnectionId())) {
            if (!processedRetryPacket) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-17.2.5
                // "A client MUST accept and process at most one Retry packet for each
                //   connection attempt.  After the client has received and processed an
                //   Initial or Retry packet from the server, it MUST discard any
                //   subsequent Retry packets that it receives."
                processedRetryPacket = true;

                token = packet.getRetryToken();
                sender.setInitialToken(token);
                getCryptoStream(Initial).reset();  // Stream offset should restart from 0.
                byte[] peerConnectionId = packet.getSourceConnectionId();
                connectionIdManager.registerInitialPeerCid(peerConnectionId);
                connectionIdManager.registerRetrySourceConnectionId(peerConnectionId);
                log.debug("Changing destination connection id into: " + bytesToHex(peerConnectionId));
                generateInitialKeys();

                // https://tools.ietf.org/html/draft-ietf-quic-recovery-18#section-6.2.1.1
                // "A Retry or Version Negotiation packet causes a client to send another
                //   Initial packet, effectively restarting the connection process and
                //   resetting congestion control..."
                sender.getCongestionController().reset();

                try {
                    tlsEngine.startHandshake();
                } catch (IOException e) {
                    // Will not happen, as our ClientMessageSender implementation will not throw.
                }
            } else {
                log.error("Ignoring RetryPacket, because already processed one.");
            }
        }
        else {
            log.error("Discarding Retry packet, because integrity tag is invalid.");
        }
        return ProcessResult.Continue;
    }

    @Override
    public ProcessResult process(ZeroRttPacket packet, Instant time) {
        // Intentionally discarding packet without any action (servers should not send 0-RTT packets).
        return ProcessResult.Abort;
    }

    @Override
    public void process(AckFrame ackFrame, QuicPacket packet, Instant timeReceived) {
        if (peerTransportParams != null) {
            ackFrame.setDelayExponent(peerTransportParams.getAckDelayExponent());
        }
        ackProcessors.forEach(p -> p.process(ackFrame, packet.getPnSpace(), timeReceived));
    }

    @Override
    public void process(HandshakeDoneFrame handshakeDoneFrame, QuicPacket packet, Instant timeReceived) {
        synchronized (handshakeStateLock) {
            if (handshakeState.transitionAllowed(HandshakeState.Confirmed)) {
                handshakeState = HandshakeState.Confirmed;
                handshakeStateListeners.forEach(l -> l.handshakeStateChangedEvent(handshakeState));
            } else {
                log.debug("Handshake state cannot be set to Confirmed");
            }
        }
        sender.discard(PnSpace.Handshake, "HandshakeDone is received");
        // TODO: discard handshake keys:
        // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-4.10.2
        // "An endpoint MUST discard its handshake keys when the TLS handshake is confirmed"
    }


    @Override
    public void process(NewConnectionIdFrame newConnectionIdFrame, QuicPacket packet, Instant timeReceived) {
        connectionIdManager.process(newConnectionIdFrame);
    }

    @Override
    public void process(NewTokenFrame newTokenFrame, QuicPacket packet, Instant timeReceived) {
    }

    @Override
    public void process(RetireConnectionIdFrame retireConnectionIdFrame, QuicPacket packet, Instant timeReceived) {
        connectionIdManager.process(retireConnectionIdFrame, packet.getDestinationConnectionId());
    }

    @Override
    protected void immediateCloseWithError(EncryptionLevel level, int error, String errorReason) {
        if (keepAliveActor != null) {
            keepAliveActor.shutdown();
        }
        super.immediateCloseWithError(level, error, errorReason);
    }

    /**
     * Closes the connection by discarding all connection state. Do not call directly, should be called after
     * closing state or draining state ends.
     */
    @Override
    protected void terminate() {
        super.terminate();
        handshakeFinishedCondition.countDown();
        receiver.shutdown();
        socket.close();
        if (receiverThread != null) {
            receiverThread.interrupt();
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

    public void updateKeys() {
        // https://tools.ietf.org/html/draft-ietf-quic-tls-31#section-6
        // "Once the handshake is confirmed (see Section 4.1.2), an endpoint MAY initiate a key update."
        if (handshakeState == HandshakeState.Confirmed) {
            connectionSecrets.getClientSecrets(App).computeKeyUpdate(true);
        }
        else {
            log.error("Refusing key update because handshake is not yet confirmed");
        }
    }

    @Override
    public int getMaxShortHeaderPacketOverhead() {
        return 1  // flag byte
                + connectionIdManager.getCurrentPeerConnectionId().length
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
        if (!verifyConnectionIds(transportParameters)) {
            return;
        }

        if (versionNegotiationStatus == VersionNegotiationStatus.VersionChangeUnconfirmed) {
            verifyVersionNegotiation(transportParameters);
        }

        peerTransportParams = transportParameters;
        if (flowController == null) {
            flowController = new FlowControl(Role.Client, peerTransportParams.getInitialMaxData(),
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
        connectionIdManager.registerPeerCidLimit(peerTransportParams.getActiveConnectionIdLimit());

        determineIdleTimeout(transportParams.getMaxIdleTimeout(), peerTransportParams.getMaxIdleTimeout());

        connectionIdManager.setInitialStatelessResetToken(peerTransportParams.getStatelessResetToken());

        if (processedRetryPacket) {
            if (peerTransportParams.getRetrySourceConnectionId() == null ||
                    ! connectionIdManager.validateRetrySourceConnectionId(peerTransportParams.getRetrySourceConnectionId())) {
                immediateCloseWithError(Handshake, TRANSPORT_PARAMETER_ERROR.value, "incorrect retry_source_connection_id transport parameter");
            }
        }
        else {
            if (peerTransportParams.getRetrySourceConnectionId() != null) {
                immediateCloseWithError(Handshake, TRANSPORT_PARAMETER_ERROR.value, "unexpected retry_source_connection_id transport parameter");
            }
        }
    }

    private void setZeroRttTransportParameters(TransportParameters rememberedTransportParameters) {
        determineIdleTimeout(transportParams.getMaxIdleTimeout(), rememberedTransportParameters.getMaxIdleTimeout());

        // max_udp_payload_size not used by Kwik

        flowController = new FlowControl(Role.Client,
                rememberedTransportParameters.getInitialMaxData(),
                rememberedTransportParameters.getInitialMaxStreamDataBidiLocal(),
                rememberedTransportParameters.getInitialMaxStreamDataBidiRemote(),
                rememberedTransportParameters.getInitialMaxStreamDataUni(),
                log);
        streamManager.setFlowController(flowController);

        streamManager.setInitialMaxStreamsBidi(rememberedTransportParameters.getInitialMaxStreamsBidi());
        streamManager.setInitialMaxStreamsUni(rememberedTransportParameters.getInitialMaxStreamsUni());

        // disable_active_migration not (yet) used by Kwik (a TODO)

        connectionIdManager.registerPeerCidLimit(rememberedTransportParameters.getActiveConnectionIdLimit());
    }

    private void verifyVersionNegotiation(TransportParameters transportParameters) {
        assert versionNegotiationStatus == VersionNegotiationStatus.VersionChangeUnconfirmed;
        TransportParameters.VersionInformation versionInformation = transportParameters.getVersionInformation();
        if (versionInformation == null || !versionInformation.getChosenVersion().equals(quicVersion.getVersion())) {
            // https://www.ietf.org/archive/id/draft-ietf-quic-version-negotiation-08.html
            // "clients MUST validate that the server's Chosen Version is equal to the negotiated version; if they do not
            //  match, the client MUST close the connection with a version negotiation error. "
            log.error(String.format("HIERO: connection version: %s, version info: %s", quicVersion, versionInformation));
            immediateCloseWithError(Handshake, VERSION_NEGOTIATION_ERROR.value, "Chosen version does not match packet version");
        }
        else {
            versionNegotiationStatus = VersionNegotiationStatus.VersionNegotiated;
            log.info(String.format("Version negotiation resulted in changing version from %s to %s", originalVersion, quicVersion));
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
            if (transportParameters.getInitialSourceConnectionId() == null) {
                immediateCloseWithError(Handshake, TRANSPORT_PARAMETER_ERROR.value, "missing initial_source_connection_id transport parameter");
            }
            else {
                immediateCloseWithError(Handshake, TRANSPORT_PARAMETER_ERROR.value, "missing original_destination_connection_id transport parameter");
            }
            return false;
        }

        // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-7.3
        // "An endpoint MUST treat the following as a connection error of type TRANSPORT_PARAMETER_ERROR or PROTOCOL_VIOLATION:
        //   *  a mismatch between values received from a peer in these transport parameters and the value sent in the
        //      corresponding Destination or Source Connection ID fields of Initial packets."
        if (! Arrays.equals(connectionIdManager.getCurrentPeerConnectionId(), transportParameters.getInitialSourceConnectionId())) {
            log.error("Source connection id does not match corresponding transport parameter");
            immediateCloseWithError(Handshake, PROTOCOL_VIOLATION.value, "initial_source_connection_id transport parameter does not match");
            return false;
        }
        if (! Arrays.equals(connectionIdManager.getOriginalDestinationConnectionId(), transportParameters.getOriginalDestinationConnectionId())) {
            log.error("Original destination connection id does not match corresponding transport parameter");
            immediateCloseWithError(Handshake, PROTOCOL_VIOLATION.value, "original_destination_connection_id transport parameter does not match");
            return false;
        }

        return true;
    }

    /**
     * Abort connection due to a fatal error in this client. No message is sent to peer; just inform client it's all over.
     * @param error  the exception that caused the trouble
     */
    @Override
    public void abortConnection(Throwable error) {
        connectionState = Status.Closing;

        if (error != null) {
            log.error("Aborting connection because of error", error);
        }
        handshakeFinishedCondition.countDown();
        sender.stop();
        terminate();
        streamManager.abortAll();
    }

    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-5.1.2
    // "An endpoint can change the connection ID it uses for a peer to
    //   another available one at any time during the connection. "
    public byte[] nextDestinationConnectionId() {
        byte[] newConnectionId = connectionIdManager.nextPeerId();
        if (newConnectionId != null) {
            log.debug("Switching to next destination connection id: " + bytesToHex(newConnectionId));
        }
        else {
            log.debug("Cannot switch to next destination connection id: no connection id's available");
        }
        return newConnectionId;
    }

    @Override
    protected boolean checkForStatelessResetToken(ByteBuffer data) {
        byte[] tokenCandidate = new byte[16];
        data.position(data.limit() - 16);
        data.get(tokenCandidate);
        boolean isStatelessReset = connectionIdManager.isStatelessResetToken(tokenCandidate);
        return isStatelessReset;
    }

    public byte[][] newConnectionIds(int count, int retirePriorTo) {
        byte[][] newConnectionIds = new byte[count][];

        for (int i = 0; i < count; i++) {
            ConnectionIdInfo cid = connectionIdManager.sendNewConnectionId(retirePriorTo);
            if (cid != null) {
                newConnectionIds[i] = cid.getConnectionId();
                log.debug("New generated source connection id", cid.getConnectionId());
            }
        }
        sender.flush();
        
        return newConnectionIds;
    }

    public void retireDestinationConnectionId(Integer sequenceNumber) {
        connectionIdManager.retireConnectionId(sequenceNumber);
    }

    @Override
    protected SenderImpl getSender() {
        return sender;
    }

    @Override
    protected GlobalAckGenerator getAckGenerator() {
        return ackGenerator;
    }

    @Override
    protected TlsClientEngine getTlsEngine() {
        return tlsEngine;
    }

    @Override
    protected StreamManager getStreamManager() {
        return streamManager;
    }

    @Override
    protected int getSourceConnectionIdLength() {
        return connectionIdManager.getConnectionIdLength();
    }

    @Override
    public byte[] getSourceConnectionId() {
        return connectionIdManager.getCurrentConnectionId();
    }

    public Map<Integer, ConnectionIdInfo> getSourceConnectionIds() {
        return connectionIdManager.getAllConnectionIds();
    }

    @Override
    public byte[] getDestinationConnectionId() {
        return connectionIdManager.getCurrentPeerConnectionId();
    }

    public Map<Integer, ConnectionIdInfo> getDestinationConnectionIds() {
        return connectionIdManager.getAllPeerConnectionIds();
    }

    @Override
    public void setPeerInitiatedStreamCallback(Consumer<QuicStream> streamProcessor) {
        streamManager.setPeerInitiatedStreamCallback(streamProcessor);
    }

    // For internal use only.
    @Override
    public long getInitialMaxStreamData() {
        return transportParams.getInitialMaxStreamDataBidiLocal();
    }

    @Override
    public void setMaxAllowedBidirectionalStreams(int max) {
        transportParams.setInitialMaxStreamsBidi(max);
    }

    @Override
    public void setMaxAllowedUnidirectionalStreams(int max) {
        transportParams.setInitialMaxStreamsUni(max);
    }

    @Override
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

    @Override
    public List<QuicSessionTicket> getNewSessionTickets() {
        return newSessionTickets;
    }

    public EarlyDataStatus getEarlyDataStatus() {
        return earlyDataStatus;
    }

    public void setEarlyDataStatus(EarlyDataStatus earlyDataStatus) {
        this.earlyDataStatus = earlyDataStatus;
    }

    public URI getUri() {
        try {
            return new URI("//" + host + ":" + port);
        } catch (URISyntaxException e) {
            // Impossible
            throw new IllegalStateException();
        }
    }

    @Override
    public void registerProcessor(FrameProcessor2<AckFrame> ackProcessor) {
        ackProcessors.add(ackProcessor);
    }

    @Override
    public InetSocketAddress getLocalAddress() {
        return (InetSocketAddress) socket.getLocalSocketAddress();
    }

    @Override
    public InetSocketAddress getServerAddress() {
        return new InetSocketAddress(host, port);
    }

    @Override
    public List<X509Certificate> getServerCertificateChain() {
        return tlsEngine.getServerCertificateChain();
    }

    @Override
    public boolean isConnected() {
        return connectionState == Status.Connected;
    }

    protected void trustAnyServerCertificate() {
        X509TrustManager trustAllCerts =
            new X509TrustManager() {
                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                @Override
                public void checkClientTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }
                @Override
                public void checkServerTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }
        };
        tlsEngine.setTrustManager(trustAllCerts);
        tlsEngine.setHostnameVerifier((hostname, serverCertificate) -> true);
    }

    private void enableQuantumReadinessTest(int nrDummyBytes) {
        clientHelloEnlargement = nrDummyBytes;
    }

    public static Builder newBuilder() {
        return new BuilderImpl();
    }

    public interface Builder {
        QuicClientConnectionImpl build() throws SocketException, UnknownHostException;

        Builder connectTimeout(Duration duration);

        Builder version(Version version);

        Builder initialVersion(Version version);

        Builder preferredVersion(Version version);

        Builder logger(Logger log);

        Builder sessionTicket(QuicSessionTicket ticket);

        Builder proxy(String host);

        Builder secrets(Path secretsFile);

        Builder uri(URI uri);

        Builder connectionIdLength(int length);

        Builder initialRtt(int initialRtt);

        Builder cipherSuite(TlsConstants.CipherSuite cipherSuite);

        Builder noServerCertificateCheck();

        Builder quantumReadinessTest(int nrOfDummyBytes);

        Builder clientCertificate(X509Certificate certificate);

        Builder clientCertificateKey(PrivateKey privateKey);
    }

    private static class BuilderImpl implements Builder {
        private String host;
        private int port;
        private QuicSessionTicket sessionTicket;
        private Version quicVersion = Version.getDefault();
        private Version preferredVersion;
        private Logger log = new NullLogger();
        private String proxyHost;
        private Path secretsFile;
        private Integer initialRtt;
        private Integer connectionIdLength;
        private List<TlsConstants.CipherSuite> cipherSuites = new ArrayList<>();
        private boolean omitCertificateCheck;
        private Integer quantumReadinessTest;
        private X509Certificate clientCertificate;
        private PrivateKey clientCertificateKey;

        @Override
        public QuicClientConnectionImpl build() throws SocketException, UnknownHostException {
            if (!quicVersion.isKnown() || !quicVersion.atLeast(Version.IETF_draft_29)) {
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

            QuicClientConnectionImpl quicConnection =
                    new QuicClientConnectionImpl(host, port, sessionTicket, quicVersion, preferredVersion, log, proxyHost,
                            secretsFile, initialRtt, connectionIdLength, cipherSuites, clientCertificate, clientCertificateKey);

            if (omitCertificateCheck) {
                quicConnection.trustAnyServerCertificate();
            }
            if (quantumReadinessTest != null) {
                quicConnection.enableQuantumReadinessTest(quantumReadinessTest);
            }

            return quicConnection;
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
        public Builder initialVersion(Version version) {
            quicVersion = version;
            return this;
        }

        @Override
        public Builder preferredVersion(Version version) {
            preferredVersion = version;
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

        @Override
        public Builder noServerCertificateCheck() {
            omitCertificateCheck = true;
            return this;
        }

        @Override
        public Builder quantumReadinessTest(int nrOfDummyBytes) {
            this.quantumReadinessTest = nrOfDummyBytes;
            return this;
        }

        @Override
        public Builder clientCertificate(X509Certificate certificate) {
            this.clientCertificate = certificate;
            return this;
        }

        @Override
        public Builder clientCertificateKey(PrivateKey privateKey) {
            this.clientCertificateKey = privateKey;
            return this;
        }
    }
}
