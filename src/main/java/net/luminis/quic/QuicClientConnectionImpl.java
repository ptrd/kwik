/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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
import net.luminis.quic.send.SenderImpl;
import net.luminis.quic.stream.EarlyDataStream;
import net.luminis.quic.stream.FlowControl;
import net.luminis.quic.stream.QuicStream;
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
import java.nio.file.Path;
import java.security.cert.X509Certificate;
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
    private volatile byte[] token;
    private final CountDownLatch handshakeFinishedCondition = new CountDownLatch(1);
    private final CountDownLatch drainingSignal = new CountDownLatch(1);
    private volatile TransportParameters peerTransportParams;
    private volatile FlowControl flowController;
    private DestinationConnectionIdRegistry destConnectionIds;
    private SourceConnectionIdRegistry sourceConnectionIds;
    private KeepAliveActor keepAliveActor;
    private String applicationProtocol;
    private final List<QuicSessionTicket> newSessionTickets = Collections.synchronizedList(new ArrayList<>());
    private boolean ignoreVersionNegotiation;
    private volatile EarlyDataStatus earlyDataStatus = None;
    private List<FrameProcessor2<AckFrame>> ackProcessors = new CopyOnWriteArrayList<>();
    private final List<TlsConstants.CipherSuite> cipherSuites;

    private final GlobalAckGenerator ackGenerator;
    private Integer clientHelloEnlargement;


    private QuicClientConnectionImpl(String host, int port, QuicSessionTicket sessionTicket, Version quicVersion, Logger log, String proxyHost, Path secretsFile, Integer initialRtt, Integer cidLength, List<TlsConstants.CipherSuite> cipherSuites) throws UnknownHostException, SocketException {
        super(quicVersion, Role.Client, secretsFile, log);
        log.info("Creating connection with " + host + ":" + port + " with " + quicVersion);
        this.host = host;
        this.port = port;
        serverAddress = InetAddress.getByName(proxyHost != null? proxyHost: host);
        this.sessionTicket = sessionTicket;
        this.cipherSuites = cipherSuites;

        socket = new DatagramSocket();

        idleTimer = new IdleTimer(this, log);
        sender = new SenderImpl(quicVersion, getMaxPacketSize(), socket, new InetSocketAddress(serverAddress, port),
                        this, initialRtt, log);
        idleTimer.setPtoSupplier(sender::getPto);
        ackGenerator = sender.getGlobalAckGenerator();
        registerProcessor(ackGenerator);

        receiver = new Receiver(socket, 1500, log, this::abortConnection);
        streamManager = new StreamManager(this, Role.Client, log, 10, 10);
        sourceConnectionIds = new SourceConnectionIdRegistry(cidLength, log);
        destConnectionIds = new DestinationConnectionIdRegistry(log);

        connectionState = Status.Idle;
        tlsEngine = new TlsClientEngine(new ClientMessageSender() {
            @Override
            public void send(ClientHello clientHello) {
                getCryptoStream(Initial).write(clientHello.getBytes());
                connectionState = Status.Handshaking;
                connectionSecrets.setClientRandom(clientHello.getClientRandom());
            }

            @Override
            public void send(FinishedMessage finished) {
                sendHandshakeFrameWithRetransmit(new CryptoFrame(quicVersion, finished.getBytes()));
                sender.flush();
            }
        }, this);
    }

    private void sendHandshakeFrameWithRetransmit(QuicFrame frame) {
        sender.send(frame, Handshake, this::sendHandshakeFrameWithRetransmit);
    }

    /**
     * Set up the connection with the server.
     */
    @Override
    public void connect(int connectionTimeout) throws IOException {
        connect(connectionTimeout, null);
    }

    @Override
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
    @Override
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

    @Override
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
        tlsEngine.setServerName(host);
        tlsEngine.addSupportedCiphers(cipherSuites);

        QuicTransportParametersExtension tpExtension = new QuicTransportParametersExtension(quicVersion, transportParams, Role.Client);
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
        connectionSecrets.computeEarlySecrets(tlsEngine);
    }

    @Override
    public void handshakeSecretsKnown() {
        // Server Hello provides a new secret, so:
        connectionSecrets.computeHandshakeSecrets(tlsEngine, tlsEngine.getSelectedCipher());
        hasHandshakeKeys();
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
            discard(PnSpace.Initial, "first Handshake message is being sent");
        });
    }

    @Override
    public void handshakeFinished() {
            connectionSecrets.computeApplicationSecrets(tlsEngine);
            synchronized (handshakeState) {
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

    private void discard(PnSpace pnSpace, String reason) {
        sender.discard(pnSpace, reason);
    }

    @Override
    public ProcessResult process(InitialPacket packet, Instant time) {
        destConnectionIds.replaceInitialConnectionId(packet.getSourceConnectionId());
        processFrames(packet, time);
        ignoreVersionNegotiation = true;
        return ProcessResult.Continue;
    }

    @Override
    public ProcessResult process(HandshakePacket packet, Instant time) {
        processFrames(packet, time);
        return ProcessResult.Continue;
    }

    @Override
    public ProcessResult process(ShortHeaderPacket packet, Instant time) {
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
        return ProcessResult.Continue;
    }

    @Override
    public ProcessResult process(VersionNegotiationPacket vnPacket, Instant time) {
        if (!ignoreVersionNegotiation && !vnPacket.getServerSupportedVersions().contains(quicVersion)) {
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
        if (packet.validateIntegrityTag(destConnectionIds.getCurrent())) {
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
    public void process(ConnectionCloseFrame connectionCloseFrame, QuicPacket packet, Instant timeReceived) {
        handlePeerClosing(connectionCloseFrame);
    }

    @Override
    public void process(CryptoFrame cryptoFrame, QuicPacket packet, Instant timeReceived) {
        try {
            getCryptoStream(packet.getEncryptionLevel()).add(cryptoFrame);
            log.receivedPacketInfo(getCryptoStream(packet.getEncryptionLevel()).toString());
        }
        catch (TlsProtocolException tlsError) {
            log.error("Parsing TLS message failed", tlsError);
            throw new ProtocolError("TLS error");
        }
    }

    @Override
    public void process(DataBlockedFrame dataBlockedFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(HandshakeDoneFrame handshakeDoneFrame, QuicPacket packet, Instant timeReceived) {
        synchronized (handshakeState) {
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
    public void process(MaxDataFrame maxDataFrame, QuicPacket packet, Instant timeReceived) {
        flowController.process(maxDataFrame);
    }

    @Override
    public void process(MaxStreamDataFrame maxStreamDataFrame, QuicPacket packet, Instant timeReceived) {
        try {
            flowController.process(maxStreamDataFrame);
        } catch (TransportError transportError) {
            immediateCloseWithError(EncryptionLevel.App, transportError.getTransportErrorCode().value, null);
        }
    }

    @Override
    public void process(MaxStreamsFrame maxStreamsFrame, QuicPacket packet, Instant timeReceived) {
        streamManager.process(maxStreamsFrame);
    }

    @Override
    public void process(NewConnectionIdFrame newConnectionIdFrame, QuicPacket packet, Instant timeReceived) {
        registerNewDestinationConnectionId((newConnectionIdFrame));
    }

    @Override
    public void process(NewTokenFrame newTokenFrame, QuicPacket packet, Instant timeReceived) {
    }

    @Override
    public void process(Padding paddingFrame, QuicPacket packet, Instant timeReceived) {
    }

    @Override
    public void process(PathChallengeFrame pathChallengeFrame, QuicPacket packet, Instant timeReceived) {
        PathResponseFrame response = new PathResponseFrame(quicVersion, pathChallengeFrame.getData());
        send(response, f -> {});
    }

    @Override
    public void process(PathResponseFrame pathResponseFrame, QuicPacket packet, Instant timeReceived) {
    }

    @Override
    public void process(PingFrame pingFrame, QuicPacket packet, Instant timeReceived) {
        // Intentionally left empty (nothing to do on receiving ping: will be acknowledged like any other ack-eliciting frame)
    }

    @Override
    public void process(ResetStreamFrame resetStreamFrame, QuicPacket packet, Instant timeReceived) {
    }

    @Override
    public void process(RetireConnectionIdFrame retireConnectionIdFrame, QuicPacket packet, Instant timeReceived) {
        retireSourceConnectionId(retireConnectionIdFrame);
    }

    @Override
    public void process(StopSendingFrame stopSendingFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(StreamFrame streamFrame, QuicPacket packet, Instant timeReceived) {
        try {
            streamManager.process(streamFrame);
        } catch (TransportError transportError) {
            immediateCloseWithError(EncryptionLevel.App, transportError.getTransportErrorCode().value, null);
        }
    }

    @Override
    public void process(StreamDataBlockedFrame streamDataBlockedFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(StreamsBlockedFrame streamsBlockedFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(QuicFrame frame, QuicPacket packet, Instant timeReceived) {
        log.warn("Unhandled frame type: " + frame);
    }


    private void handleIOError(IOException e) {
        System.out.println("Fatal: IO error " + e);
        System.exit(1);
    }

    @Override
    public QuicStream createStream(boolean bidirectional) {
        return streamManager.createStream(bidirectional);
    }

    @Override
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

    @Override
    protected void handlePeerClosing(ConnectionCloseFrame closing) {
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

    @Override
    protected String determineClosingErrorMessage(ConnectionCloseFrame closing) {
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

    @Override
    protected void terminate() {
        idleTimer.shutdown();
        sender.shutdown();
        receiver.shutdown();
        socket.close();
    }

    public void sendZeroRtt(QuicFrame frame, Consumer<QuicFrame> lostFrameCallback) {
        sender.send(frame, ZeroRTT, lostFrameCallback);
    }

    private void retransmitAppData(QuicFrame frame) {
        sender.send(frame, App, this::retransmitAppData);
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
        sourceConnectionIds.setActiveLimit(peerTransportParams.getActiveConnectionIdLimit());

        determineIdleTimeout(transportParams.getMaxIdleTimeout(), peerTransportParams.getMaxIdleTimeout());

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
    @Override
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
        return sourceConnectionIds.getConnectionIdlength();
    }

    @Override
    public byte[] getSourceConnectionId() {
        return sourceConnectionIds.getCurrent();
    }

    public Map<Integer, ConnectionIdInfo> getSourceConnectionIds() {
        return sourceConnectionIds.getAll();
    }

    @Override
    public byte[] getDestinationConnectionId() {
        return destConnectionIds.getCurrent();
    }

    public Map<Integer, ConnectionIdInfo> getDestinationConnectionIds() {
        return destConnectionIds.getAll();
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
    public List<X509Certificate> getServerCertificateChain() {
        return tlsEngine.getServerCertificateChain();
    }

    public void trustAll() {
        X509TrustManager trustAllCerts =
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }
        };
        tlsEngine.setTrustManager(trustAllCerts);
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
        private boolean omitCertificateCheck;
        private Integer quantumReadinessTest;

        @Override
        public QuicClientConnectionImpl build() throws SocketException, UnknownHostException {
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

            QuicClientConnectionImpl quicConnection = new QuicClientConnectionImpl(host, port, sessionTicket, quicVersion, log, proxyHost, secretsFile, initialRtt, connectionIdLength, cipherSuites);
            if (omitCertificateCheck) {
                quicConnection.trustAll();
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
    }


}
