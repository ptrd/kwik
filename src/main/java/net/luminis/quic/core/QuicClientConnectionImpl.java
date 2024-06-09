/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.core;

import net.luminis.quic.DatagramSocketFactory;
import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.QuicSessionTicket;
import net.luminis.quic.QuicStream;
import net.luminis.quic.ack.GlobalAckGenerator;
import net.luminis.quic.cid.ConnectionIdInfo;
import net.luminis.quic.cid.ConnectionIdManager;
import net.luminis.quic.crypto.CryptoStream;
import net.luminis.quic.crypto.MissingKeysException;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.NullLogger;
import net.luminis.quic.packet.*;
import net.luminis.quic.receive.RawPacket;
import net.luminis.quic.receive.Receiver;
import net.luminis.quic.send.SenderImpl;
import net.luminis.quic.stream.EarlyDataStream;
import net.luminis.quic.stream.FlowControl;
import net.luminis.quic.stream.StreamManager;
import net.luminis.quic.tls.QuicTransportParametersExtension;
import net.luminis.tls.CertificateWithPrivateKey;
import net.luminis.tls.NewSessionTicket;
import net.luminis.tls.TlsConstants;
import net.luminis.tls.extension.ApplicationLayerProtocolNegotiationExtension;
import net.luminis.tls.extension.EarlyDataExtension;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.handshake.*;
import net.luminis.tls.util.ByteUtils;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static net.luminis.quic.QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION;
import static net.luminis.quic.QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR;
import static net.luminis.quic.QuicConstants.TransportErrorCode.VERSION_NEGOTIATION_ERROR;
import static net.luminis.quic.core.EncryptionLevel.App;
import static net.luminis.quic.core.EncryptionLevel.Handshake;
import static net.luminis.quic.core.EncryptionLevel.Initial;
import static net.luminis.quic.core.QuicClientConnectionImpl.EarlyDataStatus.Accepted;
import static net.luminis.quic.core.QuicClientConnectionImpl.EarlyDataStatus.None;
import static net.luminis.quic.core.QuicClientConnectionImpl.EarlyDataStatus.Requested;
import static net.luminis.tls.util.ByteUtils.bytesToHex;


/**
 * Creates and maintains a QUIC connection with a QUIC server.
 */
public class QuicClientConnectionImpl extends QuicConnectionImpl implements QuicClientConnection, PacketProcessor, TlsStatusEventHandler, FrameProcessor {

    public static final long DEFAULT_CONNECT_TIMEOUT_IN_MILLIS = 10_000;
    public static final int DEFAULT_MAX_IDLE_TIMEOUT = 60_000;
    public static final int MIN_MAX_IDLE_TIMEOUT = 10;
    public static final int MIN_RECEIVER_BUFFER_SIZE = 1500;
    public static final long DEFAULT_MAX_STREAM_DATA = 250_000;
    public static final int MAX_DATA_FACTOR = 10;
    public static final int MAX_OPEN_PEER_INITIATED_BIDI_STREAMS = 3;
    public static final int MAX_OPEN_PEER_INITIATED_UNI_STREAMS = 3;
    // https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    // "The value of the active_connection_id_limit parameter MUST be at least 2."
    public static final int MIN_ACTIVE_CONNECTION_ID_LIMIT = 2;
    public static final int DEFAULT_ACTIVE_CONNECTION_ID_LIMIT = 2;
    // https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    // "Values below 1200 are invalid."
    public static final int MIN_MAX_UDP_PAYLOAD_SIZE = 1200;
    public static final int DEFAULT_MAX_UDP_PAYLOAD_SIZE = Receiver.MAX_DATAGRAM_SIZE;

    public enum EarlyDataStatus {
        None,
        Requested,
        Accepted,
        Refused;
    };

    private final String host;
    private final int serverPort;
    private final QuicSessionTicket sessionTicket;
    private final TlsClientEngine tlsEngine;
    private final DatagramSocket socket;
    private final InetAddress serverAddress;
    private final SenderImpl sender;
    private final Receiver receiver;
    private volatile PacketParser parser;
    private final StreamManager streamManager;
    private volatile TransportParameters transportParams;
    private final X509Certificate clientCertificate;
    private final PrivateKey clientCertificateKey;
    private KeyStore keyManager;
    private String keyManagerPrivateKeyPassword;
    private final ConnectionIdManager connectionIdManager;
    private final Version originalVersion;
    private final Version preferredVersion;
    private final DatagramSocketFactory socketFactory;
    private final long connectTimeout;
    private final ClientConnectionConfig connectionProperties;
    private volatile byte[] token;
    private final CountDownLatch handshakeFinishedCondition = new CountDownLatch(1);
    private volatile TransportParameters peerTransportParams;
    private KeepAliveActor keepAliveActor;
    private String applicationProtocol;
    private final List<QuicSessionTicket> newSessionTickets = Collections.synchronizedList(new ArrayList<>());
    private boolean ignoreVersionNegotiation;
    private volatile EarlyDataStatus earlyDataStatus = None;
    private final List<TlsConstants.CipherSuite> cipherSuites;

    private final GlobalAckGenerator ackGenerator;
    private Integer clientHelloEnlargement;
    private volatile Thread receiverThread;
    private volatile String handshakeError;
    private volatile ClientHello originalClientHello;


    private QuicClientConnectionImpl(String host, int port, String applicationProtocol, long connectTimeout,
                                     ClientConnectionConfig connectionProperties, QuicSessionTicket sessionTicket,
                                     Version originalVersion, Version preferredVersion, Logger log,
                                     String proxyHost, Path secretsFile, Integer initialRtt, Integer cidLength,
                                     List<TlsConstants.CipherSuite> cipherSuites,
                                     X509Certificate clientCertificate, PrivateKey clientCertificateKey,
                                     DatagramSocketFactory socketFactory) throws UnknownHostException, SocketException {
        super(originalVersion, Role.Client, secretsFile, log);
        this.applicationProtocol = applicationProtocol;
        this.connectTimeout = connectTimeout;
        this.connectionProperties = connectionProperties;
        log.info("Creating connection with " + host + ":" + port + " with " + originalVersion);
        this.originalVersion = originalVersion;
        this.preferredVersion = preferredVersion;
        this.host = host;
        this.serverPort = port;
        serverAddress = InetAddress.getByName(proxyHost != null? proxyHost: host);
        this.sessionTicket = sessionTicket;
        this.cipherSuites = cipherSuites;
        this.clientCertificate = clientCertificate;
        this.clientCertificateKey = clientCertificateKey;
        this.socketFactory = socketFactory != null? socketFactory: (address) -> new DatagramSocket();

        socket = this.socketFactory.createSocket(serverAddress);

        idleTimer = new IdleTimer(this, log);
        sender = new SenderImpl(quicVersion, getMaxPacketSize(), socket, new InetSocketAddress(serverAddress, port),
                        this, "", initialRtt, log);
        sender.enableAllLevels();
        idleTimer.setPtoSupplier(sender::getPto);
        ackGenerator = sender.getGlobalAckGenerator();

        receiver = new Receiver(socket, log, this::abortConnection, createPacketFilter());

        streamManager = new StreamManager(this, Role.Client, log, connectionProperties);

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
                originalClientHello = clientHello;
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

    @Override
    protected PacketFilter createProcessorChain() {
        return new CheckDestinationFilter(
                new DropDuplicatePacketsFilter(
                        new PostProcessingFilter(
                                new ClosingOrDrainingFilter(this, log))));
    }

    private Predicate<DatagramPacket> createPacketFilter() {
        return packet -> packet.getAddress().equals(serverAddress) && packet.getPort() == serverPort;
    }

    boolean handleUnprotectPacketFailure(ByteBuffer data, Exception unprotectException) {
        if (checkForStatelessResetToken(data)) {
            if (enterDrainingState()) {
                log.info("Entering draining state because stateless reset was received");
            }
            else {
                log.debug("Received stateless reset");
            }
            return true;
        }
        else {
            return false;
        }
    }

    protected TransportParameters initTransportParameters() {
        TransportParameters parameters = new TransportParameters();

        if (connectionProperties.maxIdleTimeout() > 0) {
            parameters.setMaxIdleTimeout(connectionProperties.maxIdleTimeout());
        }
        else {
            throw new IllegalArgumentException("maxIdleTimeout must be set");
        }

        if (connectionProperties.maxConnectionBufferSize() > 0) {
            parameters.setInitialMaxData(connectionProperties.maxConnectionBufferSize());
        }
        else {
            throw new IllegalArgumentException("maxConnectionBufferSize must be set");
        }

        if (connectionProperties.maxUnidirectionalStreamBufferSize() > 0) {
            parameters.setInitialMaxStreamDataUni(connectionProperties.maxUnidirectionalStreamBufferSize());
        }
        else {
            throw new IllegalArgumentException("maxBidirectionalStreamBufferSize must be set");
        }

        if (connectionProperties.maxBidirectionalStreamBufferSize() > 0) {
            parameters.setInitialMaxStreamDataBidiLocal(connectionProperties.maxBidirectionalStreamBufferSize());
            parameters.setInitialMaxStreamDataBidiRemote(connectionProperties.maxBidirectionalStreamBufferSize());
        }
        else {
            throw new IllegalArgumentException("maxBidirectionalStreamBufferSize must be set");
        }

        if (connectionProperties.maxOpenPeerInitiatedBidirectionalStreams() >= 0) {
            parameters.setInitialMaxStreamsBidi(connectionProperties.maxOpenPeerInitiatedBidirectionalStreams());
        }
        else {
            throw new IllegalArgumentException("maxOpenBidirectionalStreams must be set");
        }

        if (connectionProperties.maxOpenPeerInitiatedUnidirectionalStreams() >= 0) {
            parameters.setInitialMaxStreamsUni(connectionProperties.maxOpenPeerInitiatedUnidirectionalStreams());
        }
        else {
            throw new IllegalArgumentException("maxOpenUnidirectionalStreams must be set");
        }

        if (connectionProperties.getActiveConnectionIdLimit() >= MIN_ACTIVE_CONNECTION_ID_LIMIT) {
            parameters.setActiveConnectionIdLimit(connectionProperties.getActiveConnectionIdLimit());
        }
        else {
            throw new IllegalArgumentException("activeConnectionIdLimit must be set");
        }

        if (connectionProperties.getMaxUdpPayloadSize() >= MIN_MAX_UDP_PAYLOAD_SIZE) {
            parameters.setMaxUdpPayloadSize(connectionProperties.getMaxUdpPayloadSize());
        }
        else {
            throw new IllegalArgumentException("maxUdpPayloadSize must be set");
        }
        return parameters;
    }

    /**
     * Set up the connection with the server.
     */
    @Override
    public void connect() throws IOException {
        connect(null);
    }

    /**
     * Set up the connection with the server, enabling use of 0-RTT data.
     * The early data is sent on a bidirectional stream and the output stream is closed immediately after sending the data
     * if <code>closeOutput</code> is set in the <code>StreamEarlyData</code>.
     * If this connection object is not in the initial state, an <code>IllegalStateException</code> will be thrown, so
     * the connect method can only be successfully called once. Use the <code>isConnected</code> method to check whether
     * it can be connected.
     *
     * @param earlyData early data to send (RTT-0), each element of the list will lead to a bidirectional stream
     * @return list of streams that was created for the early data; the size of the list will be equal
     * to the size of the list of the <code>earlyData</code> parameter, but may contain <code>null</code>s if a stream
     * could not be created due to reaching the max initial streams limit.
     * @throws IOException
     */
    @Override
    public synchronized List<QuicStream> connect(List<StreamEarlyData> earlyData) throws IOException {
        if (connectionState != Status.Created) {
            throw new IllegalStateException("Cannot connect a connection that is in state " + connectionState);
        }
        if (earlyData != null && !earlyData.isEmpty() && sessionTicket == null) {
            throw new IllegalStateException("Cannot send early data without session ticket");
        }
        streamManager.initialize(connectionProperties);
        transportParams = initTransportParameters();
        transportParams.setInitialSourceConnectionId(connectionIdManager.getInitialConnectionId());
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
            boolean handshakeFinished = handshakeFinishedCondition.await(connectTimeout, TimeUnit.MILLISECONDS);
            if (!handshakeFinished) {
                abortHandshake();
                throw new ConnectException("Connection timed out after " + connectTimeout + " ms");
            }
            else if (connectionState != Status.Connected) {
                abortHandshake();
                throw new ConnectException("Handshake error: " + (handshakeError != null? handshakeError: ""));
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
                    earlyDataStream.writeEarlyData(streamEarlyData.getData(), streamEarlyData.isCloseOutput(), earlyDataSizeLeft);
                    earlyDataSizeLeft = Long.max(0, earlyDataSizeLeft - streamEarlyData.getData().length);
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
        parser = new ClientRolePacketParser(connectionSecrets, quicVersion, connectionIdManager.getConnectionIdLength(),
                connectionIdManager.getOriginalDestinationConnectionId(),
                createProcessorChain(), this::handleUnprotectPacketFailure, log);
        DatagramFilter datagramProcessingChain = new DatagramPostProcessingFilter(this::datagramProcessed,
                new DatagramParserFilter(parser));

        try {
            while (! currentThread.isInterrupted()) {
                RawPacket rawPacket = receiver.get(15);
                if (rawPacket != null) {
                    Duration processDelay = Duration.between(rawPacket.getTimeReceived(), Instant.now());
                    log.raw("Start processing packet " + ++receivedPacketCounter + " (" + rawPacket.getLength() + " bytes)", rawPacket.getData(), 0, rawPacket.getLength());
                    log.debug("Processing delay for packet #" + receivedPacketCounter + ": " + processDelay.toMillis() + " ms");

                    PacketMetaData metaData = new PacketMetaData(rawPacket.getTimeReceived(), null, receivedPacketCounter);
                    datagramProcessingChain.processDatagram(rawPacket.getData(), metaData);

                    sender.datagramProcessed(receiver.hasMore());
                }
            }
        }
        catch (InterruptedException e) {
            log.debug("Terminating receiver loop because of interrupt");
        }
        catch (Exception error) {
            log.debug("Terminating receiver loop because of error", error);
            abortConnection(error);
        }
    }

    private void generateInitialKeys() {
        connectionSecrets.computeInitialKeys(connectionIdManager.getCurrentPeerConnectionId());
    }

    private void startHandshake(String applicationProtocol, boolean withEarlyData) {
        tlsEngine.setServerName(host);
        tlsEngine.addSupportedCiphers(cipherSuites);

        handleClientAuthentication();
        
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
            tlsEngine.setNewSessionTicket(sessionTicket.getTlsSessionTicket());
        }

        try {
            tlsEngine.startHandshake();
        } catch (IOException e) {
            // Will not happen, as our ClientMessageSender implementation will not throw.
        }
    }

    private void handleClientAuthentication() {
        if (clientCertificate != null && clientCertificateKey != null) {
            tlsEngine.setClientCertificateCallback(authorities -> {
                if (! authorities.contains(clientCertificate.getIssuerX500Principal())) {
                    log.warn("Client certificate is not signed by one of the requested authorities: " + authorities);
                }
                return new CertificateWithPrivateKey(clientCertificate, clientCertificateKey);
            });
        }
        if (keyManager != null) {
            tlsEngine.setClientCertificateCallback(authorities -> {
                try {
                    List<String> aliases = Collections.list(keyManager.aliases());
                    for (String alias: aliases) {
                        X509Certificate certificate = (X509Certificate) keyManager.getCertificate(alias);
                        if (authorities.contains(certificate.getIssuerX500Principal())) {
                            Key key = keyManager.getKey(alias, keyManagerPrivateKeyPassword.toCharArray());
                            return new CertificateWithPrivateKey(certificate, (PrivateKey) key);
                        }
                    }
                    log.warn("None of the provided client certificates is signed by one of the requested authorities: " + authorities);
                    // Fallback to the first certificate in the key store.
                    if (!aliases.isEmpty()) {
                        return new CertificateWithPrivateKey((X509Certificate) keyManager.getCertificate(aliases.get(0)),
                                (PrivateKey) keyManager.getKey(aliases.get(0), keyManagerPrivateKeyPassword.toCharArray()));
                    }
                    else {
                       log.error("No client certificate found in key store");
                    }
                    return null;
                }
                catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                    log.error("Failed to extract client certificate from key store", e);
                    return null;
                }
            });
        }
    }

    @Override
    public void earlySecretsKnown() {
        if (sessionTicket != null) {
            TlsConstants.CipherSuite cipher = sessionTicket.getCipher();
            connectionSecrets.computeEarlySecrets(tlsEngine, cipher, quicVersion.getVersion());
        }
    }

    @Override
    public void handshakeSecretsKnown() {
        // Called by TLS engine when handshake secrets are known. So this is the time to compute QUIC's handshake secrets.
        connectionSecrets.computeHandshakeSecrets(tlsEngine, tlsEngine.getSelectedCipher());
        hasHandshakeKeys();
    }

    private void hasHandshakeKeys() {
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
            connectionSecrets.discardKeys(Initial);
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
        if (! packet.getVersion().equals(quicVersion.getVersion())) {
            handleVersionNegotiation(packet.getVersion());
        }
        connectionIdManager.registerInitialPeerCid(packet.getSourceConnectionId());
        processFrames(packet, time);
        ignoreVersionNegotiation = true;
        return ProcessResult.Continue;
    }

    private void handleVersionNegotiation(Version packetVersion) {
        if (! packetVersion.equals(quicVersion.getVersion())) {
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
                ((ClientRolePacketParser) parser).setOriginalDestinationConnectionId(peerConnectionId);

                // https://tools.ietf.org/html/draft-ietf-quic-recovery-18#section-6.2.1.1
                // "A Retry or Version Negotiation packet causes a client to send another
                //   Initial packet, effectively restarting the connection process and
                //   resetting congestion control..."
                sender.getCongestionController().reset();

                // https://www.rfc-editor.org/rfc/rfc9002.html#name-handling-retry-packets
                // "Other connection state, in particular cryptographic handshake messages, is retained (...)"
                CryptoStream cryptoStream = getCryptoStream(Initial);
                cryptoStream.write(originalClientHello, true);

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
    public void process(HandshakeDoneFrame handshakeDoneFrame, QuicPacket packet, Instant timeReceived) {
        synchronized (handshakeStateLock) {
            if (handshakeState.transitionAllowed(HandshakeState.Confirmed)) {
                handshakeState = HandshakeState.Confirmed;
                handshakeStateListeners.forEach(l -> l.handshakeStateChangedEvent(handshakeState));
            } else {
                log.debug("Handshake state cannot be set to Confirmed");
            }
        }
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-discarding-handshake-keys
        // "An endpoint MUST discard its Handshake keys when the TLS handshake is confirmed"
        // https://www.rfc-editor.org/rfc/rfc9001.html#handshake-confirmed
        // "At the client, the handshake is considered confirmed when a HANDSHAKE_DONE frame is received."
        sender.discard(PnSpace.Handshake, "HandshakeDone is received");
        connectionSecrets.discardKeys(Handshake);
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
    protected void immediateCloseWithError(EncryptionLevel level, long error, ErrorType errorType, String errorReason) {
        if (keepAliveActor != null) {
            keepAliveActor.shutdown();
        }
        super.immediateCloseWithError(level, error, errorType, errorReason);
    }

    @Override
    protected void cryptoProcessingErrorOcurred(Exception exception) {
        if (connectionState == Status.Handshaking) {
            handshakeError = exception.toString();
        }
        else {
            log.error("Processing crypto frame failed with ", exception);
        }
    }

    @Override
    protected void peerClosedWithError(ConnectionCloseFrame closeFrame) {
        super.peerClosedWithError(closeFrame);
        if (connectionState == Status.Handshaking) {
            handshakeError = "Server closed connection: " + determineClosingErrorMessage(closeFrame);
        }
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
            DatagramSocket newSocket = socketFactory.createSocket(serverAddress);
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
            try {
                connectionSecrets.getClientAead(App).computeKeyUpdate(true);
            } catch (MissingKeysException e) {
                throw new IllegalStateException(e);
            }
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

    void setPeerTransportParameters(TransportParameters receivedTransportParameters) {
        if (!verifyConnectionIds(receivedTransportParameters)) {
            return;
        }

        if (versionNegotiationStatus == VersionNegotiationStatus.VersionChangeUnconfirmed) {
            verifyVersionNegotiation(receivedTransportParameters);
        }

        peerTransportParams = receivedTransportParameters;
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

        processCommonTransportParameters(peerTransportParams);
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
            log.error(String.format("Chosen version is not equal to negotiated version: connection version: %s, version info: %s", quicVersion, versionInformation));
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
        if (connectionState == Status.Handshaking) {
            handshakeError = error.toString();
        }
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
    protected ConnectionIdManager getConnectionIdManager() {
        return connectionIdManager;
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
    @Deprecated
    public long getInitialMaxStreamData() {
        return transportParams.getInitialMaxStreamDataBidiLocal();
    }

    @Override
    public void setMaxAllowedBidirectionalStreams(int max) {
        if (connectionState != Status.Created) {
            throw new IllegalStateException("Cannot change setting after or while connection is being established");
        }
        connectionProperties.setMaxOpenPeerInitiatedBidirectionalStreams(max);
    }

    @Override
    public void setMaxAllowedUnidirectionalStreams(int max) {
        if (connectionState != Status.Created) {
            throw new IllegalStateException("Cannot change setting after or while connection is being established");
        }
        connectionProperties.setMaxOpenPeerInitiatedUnidirectionalStreams(max);
    }

    @Override
    public void setDefaultStreamReceiveBufferSize(long size) {
        if (connectionState != Status.Created) {
            throw new IllegalStateException("Cannot change setting after or while connection is being established");
        }
        if (size < MIN_RECEIVER_BUFFER_SIZE) {
            throw new IllegalArgumentException("Receiver buffer size must be at least " + MIN_RECEIVER_BUFFER_SIZE);
        }
        connectionProperties.setMaxBidirectionalStreamBufferSize(size);
        connectionProperties.setMaxUnidirectionalStreamBufferSize(size);
        if (connectionProperties.maxConnectionBufferSize() < size) {
            connectionProperties.setMaxConnectionBufferSize(size);
        }
    }

    @Override
    public void setDefaultUnidirectionalStreamReceiveBufferSize(long size) {
        if (size < 1024) {
            throw new IllegalArgumentException("Receiver buffer size must be at least 1024");
        }
        if (size > connectionProperties.maxConnectionBufferSize()) {
            throw new IllegalArgumentException("Unidirectional stream buffer size cannot be larger than connection buffer size");
        }
        if (connectionState == Status.Created) {
            connectionProperties.setMaxUnidirectionalStreamBufferSize(size);
        }
        else if (connectionState == Status.Connected) {
            streamManager.setDefaultUnidirectionalStreamReceiveBufferSize(size);
        }
        else {
            throw new IllegalStateException("Cannot change setting while connection is being established or closed");
        }
    }

    @Override
    public void setDefaultBidirectionalStreamReceiveBufferSize(long size) {
        if (size < 1024) {
            throw new IllegalArgumentException("Receiver buffer size must be at least 1024");
        }
        if (size > connectionProperties.maxConnectionBufferSize()) {
            throw new IllegalArgumentException("Bidirectional stream buffer size cannot be larger than connection buffer size");
        }
        if (connectionState == Status.Created) {
            connectionProperties.setMaxBidirectionalStreamBufferSize(size);
        }
        else if (connectionState == Status.Connected) {
            streamManager.setDefaultBidirectionalStreamReceiveBufferSize(size);
        }
        else {
            throw new IllegalStateException("Cannot change setting while connection is being established or closed");
        }
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
        newSessionTickets.add(new QuicSessionTicketImpl(tlsSessionTicket, peerTransportParams));
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
            return new URI("//" + host + ":" + serverPort);
        } catch (URISyntaxException e) {
            // Impossible
            throw new IllegalStateException();
        }
    }

    @Override
    public InetSocketAddress getLocalAddress() {
        return (InetSocketAddress) socket.getLocalSocketAddress();
    }

    @Override
    public InetSocketAddress getServerAddress() {
        return new InetSocketAddress(host, serverPort);
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
        System.out.println("SECURITY WARNING: INSECURE configuration! Server certificate validation is disabled; QUIC connections may be subject to man-in-the-middle attacks!");
        tlsEngine.setTrustManager(trustAllCerts);
        tlsEngine.setHostnameVerifier((hostname, serverCertificate) -> true);
    }

    protected void setTrustStore(KeyStore customTrustStore) throws KeyStoreException {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX");
            trustManagerFactory.init(customTrustStore);
            X509TrustManager trustManager = (X509TrustManager) trustManagerFactory.getTrustManagers()[0];
            tlsEngine.setTrustManager(trustManager);
        }
        catch (NoSuchAlgorithmException e) {
            // Inappropriate runtime environment (fairly impossible, because PKIX is required to be supported by JDK)
            throw new QuicRuntimeException(e);
        }
    }

    private void setKeyManager(KeyStore keyManager) {
        this.keyManager = keyManager;
    }

    private void setKeyManagerPrivateKeyPassword(String keyPassword) {
        this.keyManagerPrivateKeyPassword = keyPassword;
    }

    private void enableQuantumReadinessTest(int nrDummyBytes) {
        clientHelloEnlargement = nrDummyBytes;
    }

    @Override
    public String toString() {
        return "ClientConnection["
                + ByteUtils.bytesToHex(connectionIdManager.getOriginalDestinationConnectionId())
                + "/" + ByteUtils.bytesToHex(connectionIdManager.getInitialConnectionId())
                + "(" + getQuicVersion() + ")"
                + " with " + new InetSocketAddress(serverAddress, serverPort)
                + "]";
    }

    public static Builder newBuilder() {
        return new BuilderImpl();
    }

    public static ExtendedBuilder newExtendedBuilder() {
        return new ExtendedBuilder();
    }

    private static class BuilderImpl implements Builder {

        protected ClientConnectionConfig connectionProperties = new ClientConnectionConfig();
        private String host;
        private int port;
        private QuicSessionTicket sessionTicket;
        private QuicVersion quicVersion = QuicVersion.V1;
        private QuicVersion preferredVersion;
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
        private DatagramSocketFactory socketFactory;
        private long connectTimeoutInMillis = DEFAULT_CONNECT_TIMEOUT_IN_MILLIS;
        private String applicationProtocol = "";
        private KeyStore customTrustStore;
        private KeyStore keyManager;
        private String keyPassword;

        private BuilderImpl() {
            connectionProperties.setMaxIdleTimeout(DEFAULT_MAX_IDLE_TIMEOUT);
            connectionProperties.setMaxOpenPeerInitiatedUnidirectionalStreams(MAX_OPEN_PEER_INITIATED_UNI_STREAMS);
            connectionProperties.setMaxOpenPeerInitiatedBidirectionalStreams(MAX_OPEN_PEER_INITIATED_BIDI_STREAMS);
            connectionProperties.setMaxConnectionBufferSize(MAX_DATA_FACTOR * DEFAULT_MAX_STREAM_DATA);
            connectionProperties.setMaxUnidirectionalStreamBufferSize(DEFAULT_MAX_STREAM_DATA);
            connectionProperties.setMaxBidirectionalStreamBufferSize(DEFAULT_MAX_STREAM_DATA);
            connectionProperties.setActiveConnectionIdLimit(DEFAULT_ACTIVE_CONNECTION_ID_LIMIT);
            connectionProperties.setMaxUdpPayloadSize(DEFAULT_MAX_UDP_PAYLOAD_SIZE);
        }

        @Override
        public QuicClientConnectionImpl build() throws SocketException, UnknownHostException {
            checkBuilderArguments();

            if (cipherSuites.isEmpty()) {
                cipherSuites.add(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);
            }

            QuicClientConnectionImpl quicConnection =
                    new QuicClientConnectionImpl(host, port, applicationProtocol, connectTimeoutInMillis, connectionProperties, sessionTicket, Version.of(quicVersion),
                            Version.of(preferredVersion), log, proxyHost, secretsFile, initialRtt, connectionIdLength,
                            cipherSuites, clientCertificate, clientCertificateKey, socketFactory);

            if (omitCertificateCheck) {
                quicConnection.trustAnyServerCertificate();
            }

            if (customTrustStore != null) {
                try {
                    quicConnection.setTrustStore(customTrustStore);
                }
                catch (KeyStoreException e) {
                    // Should be thrown as checked exception, but would require (incompatible) interface change.
                    throw new RuntimeException(e);
                }
            }

            if (keyManager != null) {
                quicConnection.setKeyManager(keyManager);
                quicConnection.setKeyManagerPrivateKeyPassword(keyPassword);
            }

            if (quantumReadinessTest != null) {
                quicConnection.enableQuantumReadinessTest(quantumReadinessTest);
            }

            return quicConnection;
        }

        private void checkBuilderArguments() {
            if (host == null) {
                throw new IllegalStateException("Cannot create connection when URI is not set");
            }
            if (applicationProtocol.isBlank()) {
                throw new IllegalStateException("Application protocol must be set");
            }
            if (connectTimeoutInMillis < 1) {
                throw new IllegalArgumentException("Connect timeout must be larger than 0.");
            }
            if (initialRtt != null && initialRtt < 1) {
                throw new IllegalArgumentException("Initial RTT must be larger than 0.");
            }
            if (clientCertificate != null && keyManager != null) {
                throw new IllegalArgumentException("Cannot set both client certificate and key manager");
            }
            if (clientCertificate != null && clientCertificateKey == null) {
                throw new IllegalArgumentException("Client certificate key must be set when client certificate is set");
            }
            if (keyManager != null && keyPassword == null) {
                throw new IllegalArgumentException("Key password must be set when key manager is set");
            }
        }

        @Override
        public Builder applicationProtocol(String applicationProtocol) {
            this.applicationProtocol = Objects.requireNonNull(applicationProtocol);
            return this;
        }

        @Override
        public Builder connectTimeout(Duration duration) {
            connectTimeoutInMillis = duration.toMillis();
            return this;
        }

        @Override
        public Builder maxIdleTimeout(Duration duration) {
            if (duration.toMillis() < MIN_MAX_IDLE_TIMEOUT) {
                throw new IllegalArgumentException("Max idle timeout must be larger than " + MIN_MAX_IDLE_TIMEOUT + ".");
            }
            connectionProperties.setMaxIdleTimeout((int) duration.toMillis());
            return this;
        }

        @Override
        public Builder defaultStreamReceiveBufferSize(Long bufferSize) {
            if (bufferSize < MIN_RECEIVER_BUFFER_SIZE) {
                throw new IllegalArgumentException("Default stream receive buffer size must be larger than " + MIN_RECEIVER_BUFFER_SIZE + ".");
            }
            connectionProperties.setMaxBidirectionalStreamBufferSize(bufferSize);
            return this;
        }

        @Override
        public Builder maxOpenPeerInitiatedBidirectionalStreams(int max) {
            if (max < 0) {
                throw new IllegalArgumentException("Max open peer initiated bidirectional streams must be larger than 0.");
            }
            connectionProperties.setMaxOpenPeerInitiatedBidirectionalStreams(max);
            return this;
        }

        @Override
        public Builder maxOpenPeerInitiatedUnidirectionalStreams(int max) {
            if (max < 0) {
                throw new IllegalArgumentException("Max open peer initiated unidirectional streams must be larger than 0.");
            }
            connectionProperties.setMaxOpenPeerInitiatedUnidirectionalStreams(max);
            return this;
        }

        @Override
        public Builder version(QuicVersion version) {
            quicVersion = version;
            return this;
        }

        @Override
        public Builder initialVersion(QuicVersion version) {
            quicVersion = version;
            return this;
        }

        @Override
        public Builder preferredVersion(QuicVersion version) {
            preferredVersion = version;
            return this;
        }

        @Override
        public Builder logger(Logger log) {
            this.log = Objects.requireNonNull(log);
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
            cipherSuites.add(Objects.requireNonNull(cipherSuite));
            return this;
        }

        @Override
        public Builder noServerCertificateCheck() {
            omitCertificateCheck = true;
            return this;
        }

        @Override
        public Builder customTrustStore(KeyStore customTrustStore) {
            this.customTrustStore = customTrustStore;
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

        @Override
        public Builder clientKeyManager(KeyStore keyManager) {
            this.keyManager = keyManager;
            return this;
        }

        @Override
        public Builder clientKey(String keyPassword) {
            this.keyPassword = keyPassword;
            return this;
        }

        @Override
        public Builder socketFactory(DatagramSocketFactory socketFactory) {
            this.socketFactory = socketFactory;
            return this;
        }
    }

    /**
     * Extended builder that allows setting additional parameters, that normally don't have to be customized.
     */
    public static class ExtendedBuilder extends BuilderImpl implements Builder {

        public ExtendedBuilder activeConnectionIdLimit(int limit) {
            if (limit < MIN_ACTIVE_CONNECTION_ID_LIMIT) {
                throw new IllegalArgumentException("Active connection id limit must be at least " + MIN_ACTIVE_CONNECTION_ID_LIMIT + ".");
            }
            connectionProperties.setActiveConnectionIdLimit(limit);
            return this;
        }

        public void maxUdpPayloadSize(int maxSize) {
            if (maxSize < MIN_MAX_UDP_PAYLOAD_SIZE) {
                throw new IllegalArgumentException("Max UDP payload size must be at least " + MIN_MAX_UDP_PAYLOAD_SIZE + ".");
            }
            connectionProperties.setMaxUdpPayloadSize(maxSize);
        }
    }
}
