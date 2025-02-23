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

import tech.kwik.agent15.NewSessionTicket;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.MissingExtensionAlert;
import tech.kwik.agent15.alert.NoApplicationProtocolAlert;
import tech.kwik.agent15.engine.ServerMessageSender;
import tech.kwik.agent15.engine.TlsEngine;
import tech.kwik.agent15.engine.TlsServerEngine;
import tech.kwik.agent15.engine.TlsServerEngineFactory;
import tech.kwik.agent15.engine.TlsStatusEventHandler;
import tech.kwik.agent15.extension.ApplicationLayerProtocolNegotiationExtension;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.handshake.*;
import tech.kwik.core.ConnectionEstablishedEvent;
import tech.kwik.core.QuicStream;
import tech.kwik.core.ack.GlobalAckGenerator;
import tech.kwik.core.cid.ConnectionIdManager;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.crypto.CryptoStream;
import tech.kwik.core.frame.CryptoFrame;
import tech.kwik.core.frame.HandshakeDoneFrame;
import tech.kwik.core.frame.NewTokenFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.frame.RetireConnectionIdFrame;
import tech.kwik.core.impl.*;
import tech.kwik.core.log.LogProxy;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.*;
import tech.kwik.core.send.SenderImpl;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ApplicationProtocolSettings;
import tech.kwik.core.server.ServerConnection;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnectionRegistry;
import tech.kwik.core.socket.ServerConnectionSocketManager;
import tech.kwik.core.stream.FlowControl;
import tech.kwik.core.stream.StreamManager;
import tech.kwik.core.tls.QuicTransportParametersExtension;
import tech.kwik.core.util.Bytes;
import tech.kwik.core.util.InetTools;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import static tech.kwik.core.QuicConstants.TransportErrorCode.INVALID_TOKEN;
import static tech.kwik.core.QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION;
import static tech.kwik.core.QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR;
import static tech.kwik.core.common.EncryptionLevel.Initial;
import static tech.kwik.core.impl.QuicConnectionImpl.Status.Connected;
import static tech.kwik.core.impl.QuicConnectionImpl.Status.Handshaking;
import static tech.kwik.core.impl.QuicConnectionImpl.VersionNegotiationStatus.VersionChangeUnconfirmed;


public class ServerConnectionImpl extends QuicConnectionImpl implements ServerConnection, TlsStatusEventHandler {

    static final int TOKEN_SIZE = 37;
    private final Random random;
    private final SenderImpl sender;
    private final Version originalVersion;
    private final InetSocketAddress initialClientAddress;
    private final boolean usingIPv4;
    private final CryptoStream bufferedInitialCrypto;
    private final boolean retryRequired;
    private final GlobalAckGenerator ackGenerator;
    private final TlsServerEngine tlsEngine;
    private volatile ServerConnectionConfig configuration;
    private final ApplicationProtocolRegistry applicationProtocolRegistry;
    private final Consumer<ServerConnectionImpl> closeCallback;
    private final StreamManager streamManager;
    private final byte[] token;
    private final ConnectionIdManager connectionIdManager;
    private final ServerConnectionSocketManager socketManager;
    private volatile String negotiatedApplicationProtocol;
    private volatile long bytesReceived;
    private volatile boolean addressValidated;
    private boolean acceptEarlyData = true;
    private boolean acceptedEarlyData = false;
    private int allowedClientConnectionIds = 3;
    private boolean applicationProtocolStarted;

    /**
     * Creates a server connection implementation.
     *
     * @param originalVersion             quic version used for this connection
     * @param serverSocket                the socket that is used for sending packets
     * @param initialClientAddress        the initial client address (after handshake, clients can move to different address)
     * @param peerCid                     the connection id of the client
     * @param originalDcid                the original destination connection id used by the client
     * @param cryptoStream                stream containing already received crypto data for encryption level Initial
     * @param tlsServerEngineFactory      factory for creating tls engine
     * @param configuration               connection configuration settings
     * @param applicationProtocolRegistry the registry for application protocols this server supports
     * @param connectionRegistry          the registry for server connections
     * @param closeCallback               callback for notifying interested parties this connection is closed
     * @param log                         logger
     */
    public ServerConnectionImpl(Version originalVersion, DatagramSocket serverSocket, InetSocketAddress initialClientAddress,
                                byte[] peerCid, byte[] originalDcid, CryptoStream cryptoStream, TlsServerEngineFactory tlsServerEngineFactory,
                                ServerConnectionConfig configuration, ApplicationProtocolRegistry applicationProtocolRegistry,
                                ServerConnectionRegistry connectionRegistry, Consumer<ServerConnectionImpl> closeCallback, Logger log) {
        super(originalVersion, Role.Server, null, new LogProxy(log, originalDcid), configuration);
        this.originalVersion = originalVersion;
        this.initialClientAddress = initialClientAddress;
        usingIPv4 = InetTools.isIPv4(initialClientAddress.getAddress());
        this.bufferedInitialCrypto = cryptoStream;
        this.retryRequired = configuration.retryRequired() == ServerConnectionConfig.RetryRequired.Always;
        this.configuration = configuration;
        this.applicationProtocolRegistry = applicationProtocolRegistry;
        this.closeCallback = closeCallback;

        tlsEngine = tlsServerEngineFactory.createServerEngine(new TlsMessageSender(), this);
        tlsEngine.addSupportedCiphers(List.of(
                TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256,
                TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384,
                TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256
                // TlsConstants.CipherSuite.TLS_AES_128_CCM_SHA256 not yet support by Kwik
                // TlsConstants.CipherSuite.TLS_AES_128_CCM_8_SHA256 not used in QUIC!
        ));

        BiConsumer<Integer, String> closeWithErrorFunction = (error, reason) -> {
            immediateCloseWithError(error, reason);
        };
        connectionIdManager = new ConnectionIdManager(peerCid, originalDcid, configuration.connectionIdLength(), allowedClientConnectionIds, connectionRegistry, closeWithErrorFunction, log);
        connectionIdManager.registerClientAddress(initialClientAddress);

        idleTimer = new IdleTimer(this, log);
        socketManager = new ServerConnectionSocketManager(serverSocket, initialClientAddress);
        sender = new SenderImpl(quicVersion, getMaxPacketSize(), socketManager, this, Bytes.bytesToHex(originalDcid), configuration.initialRtt(), this.log);
        connectionIdManager.setSender(sender);

        if (! retryRequired) {
            sender.setAntiAmplificationLimit(0);
        }
        idleTimer.setPtoSupplier(sender::getPto);

        if (bufferedInitialCrypto != null) {
            bufferedInitialCrypto.setTlsEngine(tlsEngine);
            bufferedInitialCrypto.setSender(sender);
            assert(cryptoStreams.size() == 0);
            cryptoStreams.add(bufferedInitialCrypto);
        }


        ackGenerator = sender.getGlobalAckGenerator();

        if (retryRequired) {
            random = new SecureRandom();
            token = new byte[TOKEN_SIZE];
            random.nextBytes(token);
        }
        else {
            random = null;
            token = null;
        }
        connectionSecrets.computeInitialKeys(originalDcid);
        sender.start(connectionSecrets);

        streamManager = new StreamManager(this, Role.Server, log, configuration, callbackThread);

        this.log.getQLog().emitConnectionCreatedEvent(Instant.now());
    }

    @Override
    protected PacketFilter createProcessorChain() {
        return new CheckDestinationFilter(
                new DropDuplicatePacketsFilter(
                        new FramesCheckFilter(
                                new VersionNegotiationConfirmedFilter(
                                        new PostProcessingFilter(
                                                new QlogPacketFilter(
                                                        new ClosingOrDrainingFilter(this, log)))))));
    }

    PacketParser createParser() {
        return new ServerRolePacketParser(connectionSecrets, quicVersion, getSourceConnectionIdLength(), retryRequired,
                processorChain, () -> versionNegotiationStatus, log);
    }

    @Override
    public void abortConnection(Throwable error) {
        log.error(this + " aborted due to internal error", error);
        closeCallback.accept(this);
    }

    @Override
    protected boolean usingIPv4() {
        return usingIPv4;
    }

    @Override
    protected SenderImpl getSender() {
        return sender;
    }

    @Override
    protected TlsEngine getTlsEngine() {
        return tlsEngine;
    }

    @Override
    protected GlobalAckGenerator getAckGenerator() {
        return ackGenerator;
    }

    @Override
    protected StreamManager getStreamManager() {
        return streamManager;
    }

    @Override
    public ConnectionIdManager getConnectionIdManager() {
        return connectionIdManager;
    }

    @Override
    @Deprecated
    public long getInitialMaxStreamData() {
        return configuration.maxBidirectionalStreamBufferSize();
    }

    @Override
    public int getMaxShortHeaderPacketOverhead() {
        return 1  // flag byte
                + connectionIdManager.getCurrentPeerConnectionId().length
                + 4  // max packet number size, in practice this will be mostly 1
                + 16; // encryption overhead
    }

    @Override
    protected int getSourceConnectionIdLength() {
        return connectionIdManager.getInitialConnectionId().length;
    }

    @Override
    protected void cryptoProcessingErrorOcurred(Exception exception) {
    }

    public byte[] getInitialConnectionId() {
        return connectionIdManager.getInitialConnectionId();
    }

    @Override
    public byte[] getSourceConnectionId() {
        return connectionIdManager.getInitialConnectionId();
    }

    @Override
    public byte[] getDestinationConnectionId() {
        return connectionIdManager.getCurrentPeerConnectionId();
    }

    @Override
    public void earlySecretsKnown() {
        // https://www.rfc-editor.org/rfc/rfc9369.html#name-compatible-negotiation-requ
        // "Servers can accept 0-RTT and then process 0-RTT packets from the original version."
        connectionSecrets.computeEarlySecrets(tlsEngine, tlsEngine.getSelectedCipher(), originalVersion);
    }

    @Override
    public void handshakeSecretsKnown() {
        connectionSecrets.computeHandshakeSecrets(tlsEngine, tlsEngine.getSelectedCipher());
        currentEncryptionLevel = EncryptionLevel.Handshake;
    }

    @Override
    public void handshakeFinished() {
        currentEncryptionLevel = EncryptionLevel.App;
        connectionSecrets.computeApplicationSecrets(tlsEngine);
        sender.enableAppLevel();
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-discarding-handshake-keys
        // "An endpoint MUST discard its handshake keys when the TLS handshake is confirmed"
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-handshake-confirmed
        // "In this document, the TLS handshake is considered confirmed at the server when the handshake completes."
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-handshake-complete
        // "In this document, the TLS handshake is considered complete when the TLS stack has reported that the handshake
        //  is complete. This happens when the TLS stack has both sent a Finished message and verified the peer's Finished message."
        sender.discard(PnSpace.Handshake, "tls handshake confirmed");
        connectionSecrets.discardKeys(EncryptionLevel.Handshake);
        // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-4.9.2
        // "The server MUST send a HANDSHAKE_DONE frame as soon as it completes the handshake."
        sendHandshakeDone(new HandshakeDoneFrame(quicVersion.getVersion()));
        connectionState = Connected;

        synchronized (handshakeStateLock) {
            if (handshakeState.transitionAllowed(HandshakeState.Confirmed)) {
                handshakeState = HandshakeState.Confirmed;
                handshakeStateListeners.forEach(l -> l.handshakeStateChangedEvent(handshakeState));
            }
            else {
                log.debug("Handshake state cannot be set to Confirmed");
            }
        }
        emit(new ConnectionEstablishedEvent(this));

        if (!applicationProtocolStarted) {
            applicationProtocolRegistry.startApplicationProtocolConnection(negotiatedApplicationProtocol, this);
            applicationProtocolStarted = true;
        }
        connectionIdManager.handshakeFinished();
    }

    private void sendHandshakeDone(QuicFrame frame) {
        send(frame, this::sendHandshakeDone);
    }

    @Override
    public void newSessionTicketReceived(NewSessionTicket ticket) {
    }

    @Override
    public void extensionsReceived(List<Extension> extensions) throws TlsProtocolException {
        // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-8.1
        // "Unless another mechanism is used for agreeing on an application protocol, endpoints MUST use ALPN for this purpose."
        Optional<Extension> alpnExtension = extensions.stream()
                .filter(ext -> ext instanceof ApplicationLayerProtocolNegotiationExtension)
                .findFirst();
        if (alpnExtension.isEmpty()) {
            throw new MissingExtensionAlert("missing application layer protocol negotiation extension");
        }
        else {
            // "When using ALPN, endpoints MUST immediately close a connection (...) if an application protocol is not negotiated."
            List<String> requestedProtocols = ((ApplicationLayerProtocolNegotiationExtension) alpnExtension.get()).getProtocols();
            Optional<String> applicationProtocol = applicationProtocolRegistry.selectSupportedApplicationProtocol(requestedProtocols);
            if (applicationProtocol.isPresent()) {
                negotiatedApplicationProtocol = applicationProtocol.get();
                // Add negotiated protocol to TLS response (Encrypted Extensions message)
                tlsEngine.addServerExtensions(new ApplicationLayerProtocolNegotiationExtension(applicationProtocol.get()));
                // Determine configuration values based on server preferences and protocol requirements
                ApplicationProtocolConnectionFactory apFactory = applicationProtocolRegistry.getApplicationProtocolConnectionFactory(applicationProtocol.get());
                configure(apFactory, applicationProtocol.get());
            }
            else {
                throw new NoApplicationProtocolAlert(requestedProtocols);
            }
        }

        // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-8.2
        // "endpoints that receive ClientHello or EncryptedExtensions messages without the quic_transport_parameters extension
        //  MUST close the connection with an error of type 0x16d (equivalent to a fatal TLS missing_extension alert"
        Optional<Extension> tpExtension = extensions.stream()
                .filter(ext -> ext instanceof QuicTransportParametersExtension)
                .findFirst();
        if (tpExtension.isEmpty()) {
            throw new MissingExtensionAlert("missing quic transport parameters extension");
        }
        else {
            try {
                validateAndProcess(((QuicTransportParametersExtension) tpExtension.get()).getTransportParameters());
            }
            catch (TransportError transportParameterError) {
                throw new TlsProtocolException("transport parameter error", transportParameterError);
            }
        }

        TransportParameters serverTransportParams = initTransportParameters();

        // https://www.rfc-editor.org/rfc/rfc9369.html#name-version-negotiation-conside
        // "Any QUIC endpoint that supports QUIC version 2 MUST send, process, and validate the version_information
        //  transport parameter specified in [QUIC-VN] to prevent version downgrade attacks."
        serverTransportParams.setVersionInformation(new TransportParameters.VersionInformation(quicVersion.getVersion(), List.of(Version.QUIC_version_1, Version.QUIC_version_2)));
        serverTransportParams.setActiveConnectionIdLimit(allowedClientConnectionIds);
        serverTransportParams.setDisableMigration(true);
        serverTransportParams.setInitialSourceConnectionId(connectionIdManager.getInitialConnectionId());
        serverTransportParams.setOriginalDestinationConnectionId(connectionIdManager.getOriginalDestinationConnectionId());
        if (retryRequired) {
            serverTransportParams.setRetrySourceConnectionId(connectionIdManager.getInitialConnectionId());
        }
        tlsEngine.setSelectedApplicationLayerProtocol(negotiatedApplicationProtocol);
        tlsEngine.addServerExtensions(new QuicTransportParametersExtension(quicVersion.getVersion(), serverTransportParams, Role.Server));
        tlsEngine.setSessionData(quicVersion.getVersion().getBytes());
        tlsEngine.setSessionDataVerificationCallback(this::acceptSessionResumption);
    }

    private void configure(ApplicationProtocolSettings protocolSettings, String protocol) {
        if (protocolSettings.maxConcurrentPeerInitiatedUnidirectionalStreams() == ApplicationProtocolSettings.NOT_SPECIFIED) {
            log.warn("The ApplicationProtocolConnectionFactory for protocol " + protocol +
                    " does not define (override) maxConcurrentPeerInitiatedUnidirectionalStreams; this will be required in future versions of Kwik");
        }
        if (protocolSettings.maxConcurrentPeerInitiatedBidirectionalStreams() == ApplicationProtocolSettings.NOT_SPECIFIED) {
            log.warn("The ApplicationProtocolConnectionFactory for protocol " + protocol +
                    " does not define (override) maxConcurrentPeerInitiatedBidirectionalStreams; this will be required in future versions of Kwik");
        }
        configuration = configuration.merge(protocolSettings);
        streamManager.initialize(configuration);

        if (protocolSettings.enableDatagramExtension()) {
            enableDatagramExtension();
        }
    }

    TransportParameters initTransportParameters() {
        TransportParameters parameters = new TransportParameters();
        parameters.setMaxIdleTimeout(configuration.maxIdleTimeout());
        parameters.setInitialMaxStreamDataBidiLocal(configuration.maxBidirectionalStreamBufferSize());
        parameters.setInitialMaxStreamDataBidiRemote(configuration.maxBidirectionalStreamBufferSize());
        parameters.setInitialMaxStreamDataUni(configuration.maxUnidirectionalStreamBufferSize());
        parameters.setInitialMaxData(configuration.maxConnectionBufferSize());
        parameters.setInitialMaxStreamsBidi(configuration.maxOpenPeerInitiatedBidirectionalStreams());
        parameters.setInitialMaxStreamsUni(configuration.maxOpenPeerInitiatedUnidirectionalStreams());
        if (datagramExtensionStatus == DatagramExtensionStatus.EnabledReceiveOnly || datagramExtensionStatus == DatagramExtensionStatus.Enabled) {
            parameters.setMaxDatagramFrameSize(MAX_DATAGRAM_FRAME_SIZE_TRANSPORT_PARAMETER_VALUE);
        }

        return parameters;
    }

    boolean acceptSessionResumption(ByteBuffer storedSessionData) {
        // https://www.rfc-editor.org/rfc/rfc9369.html#name-tls-resumption-and-new_toke
        // "Servers MUST validate the originating version of any session ticket or token and not accept one issued from
        //  a different version."
        if (quicVersion.getVersion().equals(Version.parse(storedSessionData.getInt()))) {
            return true;
        }
        else {
            log.warn("Resumed session denied because quic versions don't match");
            return false;
        }
    }
    @Override
    public boolean isEarlyDataAccepted() {
        if (acceptEarlyData) {
            // Remember that server connection actually accepted early data
            acceptedEarlyData = true;
            log.info("Server accepted early data");
            return true;
        }
        else {
            return false;
        }
    }


    void increaseAntiAmplificationLimit(int increment) {
        bytesReceived += increment;
        if (! addressValidated) {
            sender.setAntiAmplificationLimit(3 * (int) bytesReceived);
        }
    }

    @Override
    protected boolean checkDestinationConnectionId(QuicPacket packet) {
        byte[] cid = packet.getDestinationConnectionId();
        if ((packet instanceof InitialPacket || packet instanceof ZeroRttPacket) && Arrays.equals(cid, getOriginalDestinationConnectionId())) {
            return true;
        }
        else {
            return super.checkDestinationConnectionId(packet);
        }
    }

    @Override
    public ProcessResult process(InitialPacket packet, PacketMetaData metaData) {
        assert(Arrays.equals(packet.getDestinationConnectionId(), connectionIdManager.getInitialConnectionId()) || Arrays.equals(packet.getDestinationConnectionId(), connectionIdManager.getOriginalDestinationConnectionId()));

        connectionState = Handshaking;
        if (retryRequired) {
            if (packet.getToken() == null) {
                sendRetry();
                connectionSecrets.recomputeInitialKeys(connectionIdManager.getInitialConnectionId());
                return ProcessResult.Abort;  // No further packet processing (e.g. ack generation).
            }
            else if (!Arrays.equals(packet.getToken(), token)) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-33#section-8.1.2
                // "If a server receives a client Initial that can be unprotected but contains an invalid Retry token,
                // (...), the server SHOULD immediately close (Section 10.2) the connection with an INVALID_TOKEN error."
                immediateCloseWithError(INVALID_TOKEN.value, null);
                return ProcessResult.Abort;
            }
            else {
                // Receiving a valid token implies address is validated.
                addressValidated = true;
                sender.unsetAntiAmplificationLimit();
                // Valid token, proceed as usual.
                processFrames(packet, metaData);
                return ProcessResult.Continue;
            }
        }
        else {
            processFrames(packet, metaData);
            return ProcessResult.Continue;
        }
    }

    @Override
    protected void postProcessCrypto(CryptoFrame cryptoFrame, QuicPacket packet, Instant timeReceived) throws TlsProtocolException {
        if (packet.getEncryptionLevel() == Initial && bufferedInitialCrypto != null) {
            if (bufferedInitialCrypto.getBufferedMessagesCount() > 0) {
                bufferedInitialCrypto.processBufferedMessages();
            }
        }
    }

    private void sendRetry() {
        try {
            RetryPacket retry = new RetryPacket(quicVersion.getVersion(), connectionIdManager.getInitialConnectionId(), getDestinationConnectionId(), getOriginalDestinationConnectionId(), token);
            byte[] packetBytes = retry.generatePacketBytes(null);  // Retry packet is not encrypted, so no keys needed.
            Instant timeSent = socketManager.send(ByteBuffer.wrap(packetBytes), initialClientAddress);
            log.sent(timeSent, retry);
            log.getQLog().emitPacketSentEvent(retry, timeSent);
        }
        catch (IOException e) {
            log.error("Sending retry packet failed", e);
        }
    }

    @Override
    public ProcessResult process(ShortHeaderPacket packet, PacketMetaData metaData) {
        connectionIdManager.registerConnectionIdInUse(packet.getDestinationConnectionId());
        processFrames(packet, metaData);
        return ProcessResult.Continue;
    }

    @Override
    public ProcessResult process(VersionNegotiationPacket packet, PacketMetaData packetMetaData) {
        // Intentionally discarding packet without any action (clients should not send Version Negotiation packets).
        return ProcessResult.Abort;
    }

    @Override
    public ProcessResult process(HandshakePacket packet, PacketMetaData metaData) {
        if (! addressValidated) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-8.1
            // "In particular, receipt of a packet protected with Handshake keys confirms that the peer successfully processed
            //  an Initial packet. Once an endpoint has successfully processed a Handshake packet from the peer, it can consider
            //  the peer address to have been validated."
            addressValidated = true;
            sender.unsetAntiAmplificationLimit();
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2.2.1
        // "A server stops sending and processing Initial packets when it receives its first Handshake packet. "
        sender.discard(PnSpace.Initial, "first handshake packet received");  // Only discards when not yet done.
        processFrames(packet, metaData);
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-discarding-initial-keys
        // "a server MUST discard Initial keys when it first successfully processes a Handshake packet"
        connectionSecrets.discardKeys(Initial);

        return ProcessResult.Continue;
    }

    @Override
    public ProcessResult process(RetryPacket packet, PacketMetaData metaData) {
        // Intentionally discarding packet without any action (clients should not send Retry packets).
        return ProcessResult.Abort;
    }

    @Override
    public ProcessResult process(ZeroRttPacket packet, PacketMetaData metaData) {
        if (acceptedEarlyData) {
            if (! applicationProtocolStarted) {
                applicationProtocolRegistry.startApplicationProtocolConnection(negotiatedApplicationProtocol, this);
                applicationProtocolStarted = true;
            }

            processFrames(packet, metaData);
        }
        else {
            log.warn("Ignoring 0-RTT packet because server connection does not accept early data.");
        }
        return ProcessResult.Continue;
    }

    @Override
    public void process(HandshakeDoneFrame handshakeDoneFrame, QuicPacket packet, PacketMetaData metaData) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.20
        // "A server MUST treat receipt of a HANDSHAKE_DONE frame as a connection error of type PROTOCOL_VIOLATION."
        immediateCloseWithError(PROTOCOL_VIOLATION.value, "unexpected handshake done frame");
    }

    @Override
    public void process(NewTokenFrame newTokenFrame, QuicPacket packet, PacketMetaData metaData) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.7
        // " A server MUST treat receipt of a NEW_TOKEN frame as a connection error of type PROTOCOL_VIOLATION."
        immediateCloseWithError(PROTOCOL_VIOLATION.value, "unexpected new token frame");
    }

    @Override
    public void process(RetireConnectionIdFrame retireConnectionIdFrame, QuicPacket packet, PacketMetaData metaData) {
        connectionIdManager.process(retireConnectionIdFrame, packet.getDestinationConnectionId());
    }

    /**
     * Trivial (do nothing else) override to make method accessible in this package.
     * @param cause
     */
    @Override
    protected void connectionError(TransportError cause) {
        super.connectionError(cause);
    }

    @Override
    protected void terminate() {
        super.terminate(() -> {
            String statsSummary = getStats().toString().replace("\n", "    ");
            log.info(String.format("Stats for connection %s: %s", Bytes.bytesToHex(connectionIdManager.getInitialConnectionId()), statsSummary));
        });
        log.getQLog().emitConnectionTerminatedEvent();
        closeCallback.accept(this);
    }

    private void validateAndProcess(TransportParameters transportParameters) throws TransportError {
        validateTransportParameters(transportParameters);

        TransportParameters.VersionInformation versionInformation = transportParameters.getVersionInformation();
        if (versionInformation != null) {
            Optional<Version> clientPreferred = versionInformation.getOtherVersions().stream()
                    // Filter out versions reserved to exercise version negotiation (0x?a?a?a?a) and unknown versions.
                    .filter(version -> version.isV1V2()).findFirst();
            if (!clientPreferred.equals(Optional.of(quicVersion.getVersion()))) {
                log.info(String.format("Switching from initial version %s to client's preferred version %s.", quicVersion, clientPreferred));
                versionNegotiationStatus = VersionNegotiationStatus.VersionChangeUnconfirmed;
                quicVersion.setVersion(clientPreferred.get());
                connectionSecrets.recomputeInitialKeys();
            }
        }

        determineIdleTimeout(configuration.maxIdleTimeout(), transportParameters.getMaxIdleTimeout());

        connectionIdManager.registerPeerCidLimit(transportParameters.getActiveConnectionIdLimit());

        flowController = new FlowControl(Role.Server, transportParameters.getInitialMaxData(),
                transportParameters.getInitialMaxStreamDataBidiLocal(), transportParameters.getInitialMaxStreamDataBidiRemote(),
                transportParameters.getInitialMaxStreamDataUni(), log);
        streamManager.setFlowController(flowController);

        processCommonTransportParameters(transportParameters);
    }

    protected void validateTransportParameters(TransportParameters transportParameters) throws TransportError {
        super.validateTransportParameters(transportParameters);

        if (!connectionIdManager.validateInitialPeerConnectionId(transportParameters.getInitialSourceConnectionId())) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-7.3
            // "An endpoint MUST treat absence of the initial_source_connection_id transport parameter from either
            //  endpoint (...) as a connection error of type TRANSPORT_PARAMETER_ERROR."
            // "An endpoint MUST treat the following as a connection error of type TRANSPORT_PARAMETER_ERROR or
            //  PROTOCOL_VIOLATION: a mismatch between values received from a peer in these transport parameters and the
            //  value sent in the corresponding Destination or Source Connection ID fields of Initial packets."
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
        // "A client MUST NOT include any server-only transport parameter: original_destination_connection_id,
        //  preferred_address, retry_source_connection_id, or stateless_reset_token. A server MUST treat receipt of any
        //  of these transport parameters as a connection error of type TRANSPORT_PARAMETER_ERROR."
        if (transportParameters.getOriginalDestinationConnectionId() != null || transportParameters.getPreferredAddress() != null
                || transportParameters.getRetrySourceConnectionId() != null || transportParameters.getStatelessResetToken() != null) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
    }

    @Override
    public InetAddress getInitialClientAddress() {
        return initialClientAddress.getAddress();
    }

    private class TlsMessageSender implements ServerMessageSender {
        @Override
        public void send(ServerHello sh) {
            CryptoStream cryptoStream = getCryptoStream(Initial);
            cryptoStream.write(sh, false);
            log.sentPacketInfo(cryptoStream.toStringSent());
        }

        @Override
        public void send(EncryptedExtensions ee) {
            getCryptoStream(EncryptionLevel.Handshake).write(ee, false);
        }

        @Override
        public void send(CertificateMessage cm) throws IOException {
            getCryptoStream(EncryptionLevel.Handshake).write(cm, false);
        }

        @Override
        public void send(CertificateVerifyMessage cv) throws IOException {
            getCryptoStream(EncryptionLevel.Handshake).write(cv, false);
        }

        @Override
        public void send(FinishedMessage finished) throws IOException {
            CryptoStream cryptoStream = getCryptoStream(EncryptionLevel.Handshake);
            cryptoStream.write(finished, false);
            log.sentPacketInfo(cryptoStream.toStringSent());
        }

        @Override
        public void send(NewSessionTicketMessage newSessionTicket) throws IOException {
            CryptoStream cryptoStream = getCryptoStream(EncryptionLevel.App);
            cryptoStream.write(newSessionTicket, true);
        }
    }

    public boolean isClosed() {
        return connectionState == Status.Closed;
    }

    public byte[] getOriginalDestinationConnectionId() {
        return connectionIdManager.getOriginalDestinationConnectionId();
    }

    public List<byte[]> getActiveConnectionIds() {
        return connectionIdManager.getActiveConnectionIds();
    }

    @Override
    public void setMaxAllowedBidirectionalStreams(int max) {
        throw new UnsupportedOperationException("Not implemented for server connection."
                + "If you really need this functionality, create an issue at https://github.com/ptrd/kwik/issues");
    }

    @Override
    public void setMaxAllowedUnidirectionalStreams(int max) {
        throw new UnsupportedOperationException("Not implemented for server connection."
                + "If you really need this functionality, create an issue at https://github.com/ptrd/kwik/issues");
    }

    @Override
    public void setDefaultStreamReceiveBufferSize(long size) {
        setDefaultUnidirectionalStreamReceiveBufferSize(size);
        setDefaultBidirectionalStreamReceiveBufferSize(size);
    }

    @Override
    public void setDefaultUnidirectionalStreamReceiveBufferSize(long size) {
        assert applicationProtocolStarted;
        if (size < 1024) {
            throw new IllegalArgumentException("Buffer size must be at least 1024");
        }
        if (size > configuration.maxConnectionBufferSize()) {
            throw new IllegalArgumentException("Buffer size cannot be larger than connection buffer size");
        }
        streamManager.setDefaultUnidirectionalStreamReceiveBufferSize(size);
    }

    @Override
    public void setDefaultBidirectionalStreamReceiveBufferSize(long size) {
        assert applicationProtocolStarted;
        if (size < 1024) {
            throw new IllegalArgumentException("Buffer size must be at least 1024");
        }
        if (size > configuration.maxConnectionBufferSize()) {
            throw new IllegalArgumentException("Buffer size cannot be larger than connection buffer size");
        }
        streamManager.setDefaultBidirectionalStreamReceiveBufferSize(size);
    }

    @Override
    public void setPeerInitiatedStreamCallback(Consumer<QuicStream> streamConsumer) {
        streamManager.setPeerInitiatedStreamCallback(streamConsumer);
    }

    @Override
    public String toString() {
        return "ServerConnection["
                + Bytes.bytesToHex(connectionIdManager.getOriginalDestinationConnectionId())
                + "/" + Bytes.bytesToHex(connectionIdManager.getInitialConnectionId())
                + "(" + getQuicVersion() + ")"
                + " " + initialClientAddress
                + "]";
    }

    class VersionNegotiationConfirmedFilter extends BasePacketFilter {

        public VersionNegotiationConfirmedFilter(PacketFilter next) {
            super(next);
        }

        @Override
        public void processPacket(QuicPacket packet, PacketMetaData metaData) throws TransportError {
            if (versionNegotiationStatus == VersionChangeUnconfirmed) {
                if (packet.getVersion().equals(quicVersion.getVersion())) {
                    versionNegotiationStatus = VersionNegotiationStatus.VersionNegotiated;
                }
            }
            next(packet, metaData);
        }
    }
}
