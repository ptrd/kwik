/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.impl;

import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.ErrorAlert;
import tech.kwik.agent15.engine.TlsEngine;
import tech.kwik.core.*;
import tech.kwik.core.ack.GlobalAckGenerator;
import tech.kwik.core.cid.ConnectionIdManager;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.concurrent.DaemonThreadFactory;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.crypto.CryptoStream;
import tech.kwik.core.frame.*;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.BasePacketFilter;
import tech.kwik.core.packet.PacketFilter;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.recovery.RecoveryManager;
import tech.kwik.core.send.SenderImpl;
import tech.kwik.core.stream.FlowControl;
import tech.kwik.core.stream.StreamManager;
import tech.kwik.core.util.ProgressivelyIncreasingRateLimiter;
import tech.kwik.core.util.RateLimiter;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.function.Function;

import static tech.kwik.core.ConnectionTerminatedEvent.CloseReason;
import static tech.kwik.core.ConnectionTerminatedEvent.CloseReason.ConnectionLost;
import static tech.kwik.core.QuicConstants.TransportErrorCode.INTERNAL_ERROR;
import static tech.kwik.core.QuicConstants.TransportErrorCode.NO_ERROR;
import static tech.kwik.core.QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION;
import static tech.kwik.core.common.EncryptionLevel.App;
import static tech.kwik.core.common.EncryptionLevel.Handshake;
import static tech.kwik.core.common.EncryptionLevel.Initial;
import static tech.kwik.core.impl.QuicConnectionImpl.ErrorType.APPLICATION_ERROR;
import static tech.kwik.core.impl.QuicConnectionImpl.ErrorType.QUIC_LAYER_ERROR;
import static tech.kwik.core.send.Sender.NO_RETRANSMIT;
import static tech.kwik.core.util.Bytes.bytesToHex;


public abstract class QuicConnectionImpl implements QuicConnection, PacketProcessor, FrameProcessor, PacketFilter {

    public enum Status {
        Created,
        Handshaking,
        Connected,
        Closing,
        Draining,
        Closed,
        Failed;

        public boolean closingOrDraining() {
            return this == Closing || this == Draining || this == Closed || this == Failed;
        }

        public boolean isClosing() {
            return this == Closing;
        }
    }

    protected enum DatagramExtensionStatus {
        Disabled,
        Enable,
        Enabled,
        EnabledReceiveOnly
    }

    public enum VersionNegotiationStatus {
        NotStarted,
        VersionChangeUnconfirmed,
        VersionNegotiated
    }

    protected enum ErrorType {
        QUIC_LAYER_ERROR,
        APPLICATION_ERROR
    }

    // https://www.rfc-editor.org/rfc/rfc9221.html#section-3
    // "For most uses of DATAGRAM frames, it is RECOMMENDED to send a value of 65535 in the max_datagram_frame_size
    //  transport parameter to indicate that this endpoint will accept any DATAGRAM frame that fits inside a QUIC packet."
    protected static final int MAX_DATAGRAM_FRAME_SIZE_TRANSPORT_PARAMETER_VALUE = 65535;

    protected final VersionHolder quicVersion;
    private final Role role;
    protected final Logger log;
    protected final PacketFilter processorChain;
    protected VersionNegotiationStatus versionNegotiationStatus = VersionNegotiationStatus.NotStarted;

    protected final ConnectionSecrets connectionSecrets;
    protected volatile HandshakeState handshakeState = HandshakeState.Initial;
    protected final Object handshakeStateLock = new Object();
    protected List<HandshakeStateListener> handshakeStateListeners = new CopyOnWriteArrayList<>();
    protected volatile EncryptionLevel currentEncryptionLevel;
    protected IdleTimer idleTimer;
    protected final List<Runnable> postProcessingActions = new ArrayList<>();
    protected final List<CryptoStream> cryptoStreams = new ArrayList<>();
    private FrameReceivedListener<AckFrame> recoveryManager;
    // https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    // "If this value is absent, a default value of 3 is assumed (indicating a multiplier of 8)."
    protected volatile int peerAckDelayExponent = 3;
    protected final boolean useStrictSmallestAllowedMaximumDatagramSize;

    protected volatile FlowControl flowController;

    protected volatile Status connectionState;

    private RateLimiter closeFramesSendRateLimiter;
    private volatile ConnectionCloseFrame lastConnectionCloseFrameSent;
    private final ScheduledExecutorService scheduler;
    private ConnectionListener connectionListener;
    protected final ExecutorService callbackThread;

    // https://datatracker.ietf.org/doc/html/rfc9221  Datagram Extension
    protected volatile DatagramExtensionStatus datagramExtensionStatus = DatagramExtensionStatus.Disabled;
    private volatile int maxDatagramFrameSize;
    private volatile Consumer<byte[]> datagramHandler;
    private volatile ExecutorService datagramHandlerExecutor;


    protected QuicConnectionImpl(Version originalVersion, Role role, Path secretsFile, Logger log, ConnectionConfig settings) {
        this.quicVersion = new VersionHolder(originalVersion);
        this.role = role;
        this.log = log;
        useStrictSmallestAllowedMaximumDatagramSize = settings != null? settings.useStrictSmallestAllowedMaximumDatagramSize(): false;

        processorChain = createProcessorChain();

        connectionSecrets = new ConnectionSecrets(quicVersion, role, secretsFile, log);

        connectionState = Status.Created;
        closeFramesSendRateLimiter = new ProgressivelyIncreasingRateLimiter();
        scheduler = Executors.newScheduledThreadPool(1, new DaemonThreadFactory("scheduler"));
        callbackThread = Executors.newSingleThreadExecutor(new DaemonThreadFactory("callback-executor"));
        currentEncryptionLevel = Initial;
    }

    public void addHandshakeStateListener(RecoveryManager recoveryManager) {
        handshakeStateListeners.add(recoveryManager);
    }

    /**
     * Queues a frame for sending.
     * As this method does not flush the sender, it should only be called from a context that ensures the sender is
     * flushed, e.g. from a method that processes a received packet (because this class will flush the sender when
     * all frames in a packet have been processed, by calling Sender.packetProcessed()).
     * @param frame  the frame to send
     * @param lostFrameCallback  function called when packet that contains the frame is lost
     */
    public void send(QuicFrame frame, Consumer<QuicFrame> lostFrameCallback) {
        send(frame, lostFrameCallback, false);
    }

    public void send(QuicFrame frame, Consumer<QuicFrame> lostFrameCallback, boolean flush) {
        getSender().send(frame, App, lostFrameCallback);
        if (flush) {
            getSender().flush();
        }
    }

    public void send(QuicFrame frame, EncryptionLevel level, Consumer<QuicFrame> lostFrameCallback, boolean flush) {
        getSender().send(frame, level, lostFrameCallback);
        if (flush) {
            getSender().flush();
        }
    }

    public void send(Function<Integer, QuicFrame> frameSupplier, int minimumSize, EncryptionLevel level, Consumer<QuicFrame> lostCallback) {
        getSender().send(frameSupplier, minimumSize, level, lostCallback);
    }

    public void send(Function<Integer, QuicFrame> frameSupplier, int minimumSize, EncryptionLevel level, Consumer<QuicFrame> lostCallback, boolean flush) {
        getSender().send(frameSupplier, minimumSize, level, lostCallback);
        if (flush) {
            getSender().flush();
        }
    }

    @Override
    public void sendDatagram(byte[] data) {
        if (canSendDatagram()) {
            if (data.length > maxDatagramDataSize()) {
                throw new IllegalArgumentException("Data too large for a single datagram frame");
            }

            // https://www.rfc-editor.org/rfc/rfc9221.html#section-5
            // "When an application sends a datagram over a QUIC connection, QUIC will generate a new DATAGRAM frame and
            //  send it in the first available packet. This frame SHOULD be sent as soon as possible (...)"
            getSender().sendWithPriority(new DatagramFrame(data), App, f -> {});
        }
        else {
            throw new IllegalStateException("Datagram extension is not enabled" +
                    (datagramExtensionStatus == DatagramExtensionStatus.EnabledReceiveOnly? " for sending.":"."));
        }
    }

    @Override
    public int maxDatagramDataSize() {
        // https://www.rfc-editor.org/rfc/rfc9221.html#section-5
        // "Note that while the max_datagram_frame_size transport parameter places a limit on the maximum size of
        //  DATAGRAM frames, that limit can be further reduced by the max_udp_payload_size transport parameter and the
        //  Maximum Transmission Unit (MTU) of the path between endpoints. DATAGRAM frames cannot be fragmented;
        //  therefore, application protocols need to handle cases where the maximum datagram size is limited by other
        //  factors."
        int maxShortHeaderPacketOverhead = 1 + getDestinationConnectionId().length + 4;
        int maxEffectiveDatagramFrameSize = Integer.min(maxDatagramFrameSize, getMaxPacketSize() - maxShortHeaderPacketOverhead);
        return maxEffectiveDatagramFrameSize - DatagramFrame.getMaxMinimalFrameSize();
    }

    @Override
    public void setDatagramHandler(Consumer<byte[]> handler) {
        DaemonThreadFactory daemonThreadFactory = new DaemonThreadFactory("datagram-frame-handler");
        setDatagramHandler(handler, Executors.newSingleThreadExecutor(daemonThreadFactory));
    }

    @Override
    public void setDatagramHandler(Consumer<byte[]> handler, ExecutorService callbackExecutor) {
        datagramHandlerExecutor = Objects.requireNonNull(callbackExecutor);
        this.datagramHandler = Objects.requireNonNull(handler);
    }

    @Override
    public QuicStream createStream(boolean bidirectional) throws IOException {
        if (connectionState != Status.Connected) {
            throw new IOException("not connected");
        }

        return getStreamManager().createStream(bidirectional);
    }

    public void datagramProcessed() {
        // Processed all packets in the datagram, so not expecting more.
        getSender().packetProcessed(false);

        // Finally, execute actions that need to be executed after all responses and acks are sent.
        runPostProcessingActions();
    }

    protected void runPostProcessingActions() {
        postProcessingActions.forEach(action -> action.run());
        postProcessingActions.clear();
    }

    protected boolean checkDestinationConnectionId(QuicPacket packet) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-client-packet-handling
        // "Packets that do not match an existing connection -- based on Destination Connection ID or, if this
        //  value is zero length, local IP address and port -- are discarded."
        byte[] cid = packet.getDestinationConnectionId();
        if (getConnectionIdManager().isActiveCid(cid)) {
            return true;
        }
        else {
            log.error(String.format("Dropping packet because dcid %s is not an active connection ID.", bytesToHex(cid)));
            return false;
        }
    }

    protected void processFrames(QuicPacket packet, Instant timeReceived) {
        for (QuicFrame frame: packet.getFrames()) {
            frame.accept(this, packet, timeReceived);
        }
    }

    /**
     * Returns the length of the connection ID's this endpoint uses (and generates).
     * @return  length of the connection ID
     */
    protected abstract int getSourceConnectionIdLength();

    /**
     * Process the transport parameters that are common to client and server.
     * @param peerTransportParams  the transport parameters to process
     */
    protected void processCommonTransportParameters(TransportParameters peerTransportParams) {
        getStreamManager().setInitialMaxStreamsBidi(peerTransportParams.getInitialMaxStreamsBidi());
        getStreamManager().setInitialMaxStreamsUni(peerTransportParams.getInitialMaxStreamsUni());

        peerAckDelayExponent = peerTransportParams.getAckDelayExponent();
        getSender().setReceiverMaxAckDelay(peerTransportParams.getMaxAckDelay());

        getSender().registerMaxUdpPayloadSize(peerTransportParams.getMaxUdpPayloadSize());

        updateDatagramExtensionStatus(peerTransportParams);
    }

    private void updateDatagramExtensionStatus(TransportParameters peerTransportParams) {
        // https://www.rfc-editor.org/rfc/rfc9221.html#section-3
        // "The max_datagram_frame_size transport parameter is a unidirectional limit and indication of support of
        //  DATAGRAM frames. Application protocols that use DATAGRAM frames MAY choose to only negotiate and use them
        //  in a single direction."
        if (peerTransportParams.getMaxDatagramFrameSize() > 0) {
            if (datagramExtensionStatus == DatagramExtensionStatus.Enable) {
                datagramExtensionStatus = DatagramExtensionStatus.Enabled;
                maxDatagramFrameSize = (int) Long.min(65535, peerTransportParams.getMaxDatagramFrameSize());  // Value larger than 65535 is useless
            }
        }
        else if (datagramExtensionStatus == DatagramExtensionStatus.Enable) {
            datagramExtensionStatus = DatagramExtensionStatus.EnabledReceiveOnly;
        }
    }

    @Override
    public boolean canSendDatagram() {
        return datagramExtensionStatus == DatagramExtensionStatus.Enabled;
    }

    @Override
    public boolean canReceiveDatagram() {
        return datagramExtensionStatus == DatagramExtensionStatus.Enabled || datagramExtensionStatus == DatagramExtensionStatus.EnabledReceiveOnly;
    }

    @Override
    public boolean isDatagramExtensionEnabled() {
        return datagramExtensionStatus == DatagramExtensionStatus.Enabled;
    }

    /**
     * Returns the value of the max_datagram_frame_size transport parameter.
     * Note that this value does not indicate the real maximum size of a datagram frame.
     * @return
     */
    protected int getMaxDatagramFrameSize() {
        return maxDatagramFrameSize;
    }

    @Override
    public void processPacket(QuicPacket packet, PacketMetaData metaData) {
        ProcessResult result = packet.accept(this, metaData.timeReceived());
        if (result == ProcessResult.Abort) {
            return;
        }

        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-13.1
        // "A packet MUST NOT be acknowledged until packet protection has been successfully removed and all frames
        //  contained in the packet have been processed."
        // "Once the packet has been fully processed, a receiver acknowledges receipt by sending one or more ACK
        //  frames containing the packet number of the received packet."
        getAckGenerator().packetReceived(packet);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
        // "An endpoint restarts its idle timer when a packet from its peer is received and processed successfully."
        idleTimer.packetProcessed();
    }

    @Override
    public void process(AckFrame ackFrame, QuicPacket packet, Instant timeReceived) {
        ackFrame.setDelayExponent(peerAckDelayExponent);
        getAckGenerator().received(ackFrame, packet.getPnSpace(), timeReceived);
        recoveryManager.received(ackFrame, packet.getPnSpace(), timeReceived);
    }

    @Override
    public void process(CryptoFrame cryptoFrame, QuicPacket packet, Instant timeReceived) {
        try {
            getCryptoStream(packet.getEncryptionLevel()).add(cryptoFrame);
            log.receivedPacketInfo(getCryptoStream(packet.getEncryptionLevel()).toStringReceived());
        }
        catch (TlsProtocolException e) {
            cryptoProcessingErrorOcurred(e);
            immediateCloseWithError(quicError(e), e.getMessage());
        }
        catch (TransportError e) {
            cryptoProcessingErrorOcurred(e);
            immediateCloseWithError(e.getTransportErrorCode().value, "");
        }
    }

    protected abstract void cryptoProcessingErrorOcurred(Exception exception);

    @Override
    public void process(ConnectionCloseFrame connectionCloseFrame, QuicPacket packet, Instant timeReceived) {
        handlePeerClosing(connectionCloseFrame, packet.getEncryptionLevel());
    }

    @Override
    public void process(DataBlockedFrame dataBlockedFrame, QuicPacket packet, Instant timeReceived) {
        log.warn("Received " + dataBlockedFrame);
    }

    @Override
    public void process(DatagramFrame datagramFrame, QuicPacket packet, Instant timeReceived) {
        // https://www.rfc-editor.org/rfc/rfc9221.html#section-3
        // "An endpoint that receives a DATAGRAM frame when it has not indicated support via the transport parameter
        //  MUST terminate the connection with an error of type PROTOCOL_VIOLATION."
        if (!canReceiveDatagram()) {
            immediateCloseWithError(PROTOCOL_VIOLATION.value, "Datagram frame received, but datagram extension is not enabled");
            return;
        }
        if (datagramHandler != null) {
            datagramHandlerExecutor.submit(() -> datagramHandler.accept(datagramFrame.getData()));
        }
        else {
            log.warn("Received datagram frame, but no handler is set");
        }
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
            immediateCloseWithError(transportError.getTransportErrorCode().value, null);
        }
    }
    @Override
    public void process(MaxStreamsFrame maxStreamsFrame, QuicPacket packet, Instant timeReceived) {
        getStreamManager().process(maxStreamsFrame);
    }

    @Override
    public void process(Padding paddingFrame, QuicPacket packet, Instant timeReceived) {
    }

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-path_challenge-frames
    // "The recipient of this frame MUST generate a PATH_RESPONSE frame (...) containing the same Data value."
    @Override
    public void process(PathChallengeFrame pathChallengeFrame, QuicPacket packet, Instant timeReceived) {
        PathResponseFrame response = new PathResponseFrame(quicVersion.getVersion(), pathChallengeFrame.getData());
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-retransmission-of-informati
        // "Responses to path validation using PATH_RESPONSE frames are sent just once."
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
        try {
            getStreamManager().process(resetStreamFrame);
        }
        catch (TransportError transportError) {
            immediateCloseWithError(transportError.getTransportErrorCode().value, null);
        }
    }

    @Override
    public void process(StopSendingFrame stopSendingFrame, QuicPacket packet, Instant timeReceived) {
        getStreamManager().process(stopSendingFrame);
    }

    @Override
    public void process(StreamFrame streamFrame, QuicPacket packet, Instant timeReceived) {
        try {
            getStreamManager().process(streamFrame);
        }
        catch (TransportError transportError) {
            immediateCloseWithError(transportError.getTransportErrorCode().value, null);
        }
    }

    @Override
    public void process(StreamDataBlockedFrame streamDataBlockedFrame, QuicPacket packet, Instant timeReceived) {
        log.warn("Received " + streamDataBlockedFrame);
    }

    @Override
    public void process(StreamsBlockedFrame streamsBlockedFrame, QuicPacket packet, Instant timeReceived) {
        log.warn("Received " + streamsBlockedFrame);
    }

    protected CryptoStream getCryptoStream(EncryptionLevel encryptionLevel) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-19.6
        // "There is a separate flow of cryptographic handshake data in each
        //   encryption level"
        if (cryptoStreams.size() <= encryptionLevel.ordinal()) {
            for (int i = encryptionLevel.ordinal() - cryptoStreams.size(); i >= 0; i--) {
                cryptoStreams.add(new CryptoStream(quicVersion, encryptionLevel, connectionSecrets, role, getTlsEngine(), log, getSender()));
            }
        }
        return cryptoStreams.get(encryptionLevel.ordinal());
    }

    protected void determineIdleTimeout(long maxIdleTimout, long peerMaxIdleTimeout) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
        // "If a max_idle_timeout is specified by either peer in its transport parameters (Section 18.2), the
        //  connection is silently closed and its state is discarded when it remains idle for longer than the minimum
        //  of both peers max_idle_timeout values."
        long idleTimeout = Long.min(maxIdleTimout, peerMaxIdleTimeout);
        if (idleTimeout == 0) {
            // Value of 0 is the same as not specified.
            idleTimeout = Long.max(maxIdleTimout, peerMaxIdleTimeout);
        }
        if (idleTimeout != 0) {
            log.debug("Effective idle timeout is " + idleTimeout);
            // Initialise the idle timer that will take care of (silently) closing connection if idle longer than idle timeout
            idleTimer.setIdleTimeout(idleTimeout);
        }
        else {
            // Both or 0 or not set:
            // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-18.2
            // "Idle timeout is disabled when both endpoints omit this transport parameter or specify a value of 0."
        }
    }

    protected void silentlyCloseConnection(long idleTime) {
        if (connectionState == Status.Closing || connectionState == Status.Draining) {
            return;
        }

        emit(new ConnectionTerminatedEvent(this, idleTimer.isTailLoss()? ConnectionLost: CloseReason.IdleTimeout, false));

        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.1
        // "If a max_idle_timeout is specified by either peer (...), the connection is silently closed and its state is
        //  discarded when it remains idle for longer than the minimum of both peers max_idle_timeout values."
        getStreamManager().abortAll();
        getSender().stop();
        log.getQLog().emitConnectionClosedEvent(Instant.now());
        terminate();
    }

    protected void immediateClose() {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2
        immediateCloseWithError(NO_ERROR.value, QUIC_LAYER_ERROR, null);
    }

    /**
     * Immediately closes the connection (with or without a QUIC layer error) and enters the "closing state".
     * Connection close frame with indicated error (or "NO_ERROR") is sent to peer and after 3 x PTO, the closing state
     * is ended and all connection state is discarded.
     * If this method is called outside received-message-processing, post-processing actions (including flushing the
     * sender) should be performed by the caller.
     *
     * @param error       The error code, see https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1
     * @param errorReason
     */
    protected void immediateCloseWithError(long error, String errorReason) {
        immediateCloseWithError(error, QUIC_LAYER_ERROR, errorReason);
    }
    
    /**
     * Immediately closes the connection (with or without error) and enters the "closing state".
     * Connection close frame with indicated error (or "NO_ERROR") is sent to peer and after 3 x PTO, the closing state
     * is ended and all connection state is discarded.
     * If this method is called outside received-message-processing, post-processing actions (including flushing the
     * sender) should be performed by the caller.
     *
     * @param error       The error code, see https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-20.1.
     * @param errorType   whether the error is at the QUIC layer or an application error
     * @param errorReason
     */
    protected void immediateCloseWithError(long error, ErrorType errorType, String errorReason) {
        if (connectionState == Status.Closing || connectionState == Status.Draining) {
            log.debug("Immediate close ignored because already closing");
            return;
        }

        emit(new ConnectionTerminatedEvent(this, CloseReason.ImmediateClose, false,
                errorType == QUIC_LAYER_ERROR? error: null,
                errorType == APPLICATION_ERROR? error: null));

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2
        // "An endpoint sends a CONNECTION_CLOSE frame (Section 19.19) to terminate the connection immediately."
        getSender().stop();
        sendConnectionClose(error, errorType, errorReason);
        // "After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the closing state;"
        connectionState = Status.Closing;

        getStreamManager().abortAll();

        if (currentEncryptionLevel != Initial) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2
            // "The closing and draining connection states exist to ensure that connections close cleanly and that
            //  delayed or reordered packets are properly discarded. These states SHOULD persist for at least three
            //  times the current PTO interval as defined in [QUIC-RECOVERY]."
            int pto = getSender().getPto();
            schedule(() -> terminate(), 3 * pto, TimeUnit.MILLISECONDS);
        }
        else {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.3
            // "An endpoint that has not established state, such as a server that detects an error in an Initial packet,
            //  does not enter the closing state."
            postProcessingActions.add(() -> terminate());
        }

        log.getQLog().emitConnectionClosedEvent(Instant.now(), error, errorReason);
    }

    private void sendConnectionClose(long error, ErrorType errorType, String errorReason) {
        if (errorType == APPLICATION_ERROR && currentEncryptionLevel != App) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.3
            // "Sending a CONNECTION_CLOSE of type 0x1d in an Initial or Handshake packet could expose application state
            // or be used to alter application state. A CONNECTION_CLOSE of type 0x1d MUST be replaced by a
            // CONNECTION_CLOSE of type 0x1c when sending the frame in Initial or Handshake packets."
            sendConnectionClose(QuicConstants.TransportErrorCode.APPLICATION_ERROR.value, QUIC_LAYER_ERROR, "");
        }
        else {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.3
            // "However, prior to confirming the handshake, it is possible that more advanced packet protection keys are
            //  not available to the peer, so another CONNECTION_CLOSE frame MAY be sent in a packet that uses a lower
            //  packet protection level."
            ConnectionCloseFrame closeFrame = new ConnectionCloseFrame(quicVersion.getVersion(), error, errorType == QUIC_LAYER_ERROR, errorReason);
            switch (currentEncryptionLevel) {
                case Initial:
                    getSender().send(closeFrame, Initial);
                    break;
                case Handshake:
                    getSender().send(closeFrame, Initial);
                    getSender().send(closeFrame, Handshake);
                    break;
                case App:
                    getSender().send(closeFrame, App);
                    break;
            }
            lastConnectionCloseFrameSent = closeFrame;
        }
    }

    protected void handlePacketInClosingState(QuicPacket packet) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.2
        // "An endpoint MAY enter the draining state from the closing state if it receives a CONNECTION_CLOSE frame,
        //  which indicates that the peer is also closing or draining."
        if (packet.getFrames().stream().filter(frame -> frame instanceof ConnectionCloseFrame).findAny().isPresent()) {
            connectionState = Status.Draining;
        }
        else {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.1
            // "An endpoint in the closing state sends a packet containing a CONNECTION_CLOSE frame in response to any
            //  incoming packet that it attributes to the connection."
            // "An endpoint SHOULD limit the rate at which it generates packets in the closing state."
            assert lastConnectionCloseFrameSent != null;
            closeFramesSendRateLimiter.execute(() -> send(lastConnectionCloseFrameSent, packet.getEncryptionLevel(), NO_RETRANSMIT, false));  // No flush necessary, as this method is called while processing a received packet.
        }
    }

    protected void handlePeerClosing(ConnectionCloseFrame closing, EncryptionLevel encryptionLevel) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.2
        // "The draining state is entered once an endpoint receives a CONNECTION_CLOSE frame, which indicates that its
        //  peer is closing or draining."
        if (!connectionState.closingOrDraining()) {  // Can occur due to race condition (both peers closing simultaneously)
            emit(new ConnectionTerminatedEvent(this, CloseReason.ImmediateClose, true,
                    closing.hasTransportError()? closing.getErrorCode(): null,
                    closing.hasApplicationProtocolError()? closing.getErrorCode(): null));

            if (closing.hasError()) {
                peerClosedWithError(closing);
            }
            getSender().stop();

            getStreamManager().abortAll();

            // https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.2
            // "An endpoint that receives a CONNECTION_CLOSE frame MAY send a single packet containing a CONNECTION_CLOSE
            //  frame before entering the draining state, using a CONNECTION_CLOSE frame and a NO_ERROR code if appropriate.
            //  An endpoint MUST NOT send further packets."
            send(new ConnectionCloseFrame(quicVersion.getVersion()), encryptionLevel, NO_RETRANSMIT, false);  // No flush necessary, as this method is called while processing a received packet.

            drain();
        }
    }

    protected void peerClosedWithError(ConnectionCloseFrame closeFrame) {
    }

    private void drain() {
        connectionState = Status.Draining;
        /// https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2
        // "The closing and draining connection states exist to ensure that connections close cleanly and that delayed
        //  or reordered packets are properly discarded. These states SHOULD persist for at least three times the
        //  current Probe Timeout (PTO) interval"
        int pto = getSender().getPto();
        schedule(() -> terminate(), 3 * pto, TimeUnit.MILLISECONDS);
    }

    protected boolean enterDrainingState() {
        if (!connectionState.closingOrDraining()) {
            getSender().stop();
            getStreamManager().abortAll();
            drain();
            return true;
        }
        else {
            return false;
        }
    }

    protected void emit(ConnectionTerminatedEvent connectionDisconnectEvent) {
        if (connectionListener != null) {
            callbackThread.submit(() -> connectionListener.disconnected(connectionDisconnectEvent));
        }
        String logMessage = (connectionDisconnectEvent.closedByPeer()? "Peer is closing ": "Closing ") + this +
                (connectionDisconnectEvent.hasError()? " with error " + connectionDisconnectEvent.errorDescription(): "") + ".";
        log.info(logMessage);
    }

    protected void emit(ConnectionEstablishedEvent connectionEstablishedEvent) {
        if (connectionListener != null) {
            callbackThread.submit(() -> connectionListener.connected(connectionEstablishedEvent));
        }
    }

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

    /**
     * Closes the connection by discarding all connection state. Do not call directly, should be called after
     * closing state or draining state ends.
     */
    protected void terminate() {
        terminate(null);
    }

    protected void terminate(Runnable postSenderShutdownAction) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2
        // "Once its closing or draining state ends, an endpoint SHOULD discard all connection state."
        idleTimer.shutdown();
        getSender().shutdown(postSenderShutdownAction);
        connectionState = Status.Closed;
        scheduler.shutdown();
    }

    protected int quicError(TlsProtocolException tlsError) {
        if (tlsError instanceof ErrorAlert) {
            return 0x100 + ((ErrorAlert) tlsError).alertDescription().value;
        }
        else if (tlsError.getCause() instanceof TransportError) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-20.1
            return ((TransportError) tlsError.getCause()).getTransportErrorCode().value;
        }
        else {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-20.1
            // "INTERNAL_ERROR (0x1):  The endpoint encountered an internal error and cannot continue with the connection."
            return INTERNAL_ERROR.value;
        }
    }

    /**
     * Abort connection due to a local fatal error. No message is sent to peer; just inform application it's all over.
     * @param error  the exception that caused the trouble
     */
    public abstract void abortConnection(Throwable error);

    public int getMaxPacketSize() {
        if (useStrictSmallestAllowedMaximumDatagramSize) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-14.2
            // "An endpoint SHOULD use DPLPMTUD (Section 14.3) or PMTUD (Section 14.2.1) to determine whether the path
            //  to a destination will support a desired maximum datagram size without fragmentation. In the absence of
            //  these mechanisms, QUIC endpoints SHOULD NOT send datagrams larger than the smallest allowed maximum
            //  datagram size."
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.1, https://www.rfc-editor.org/rfc/rfc9000.html#section-14
            // "... the smallest allowed maximum datagram size of 1200 bytes"
            return 1200;
        }
        else {
            // Draft versions of the QUIC specification (e.g. https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-28)
            // allowed a minimum of 1252 bytes for IPv4 and 1232 bytes for IPv6
            // https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-28#section-14.1
            // "In the absence of these mechanisms, QUIC endpoints SHOULD NOT send IP packets larger than 1280 bytes.
            //  Assuming the minimum IP header size, this results in a QUIC maximum packet size of 1232 bytes for IPv6
            //  and 1252 bytes for IPv4."
            // and this is what several implementations still use.
            // The RFC still mentions this maximum minimum size in the context of path MTU discovery:
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-14
            // "QUIC assumes a minimum IP packet size of at least 1280 bytes. This is the IPv6 minimum size [IPv6] and is
            //  also supported by most modern IPv4 networks. Assuming the minimum IP header size of 40 bytes for IPv6 and
            //  20 bytes for IPv4 and a UDP header size of 8 bytes, this results in a maximum datagram size of 1232 bytes
            //  for IPv6 and 1252 bytes for IPv4. Thus, modern IPv4 and all IPv6 network paths are expected to be able
            //  to support QUIC."
            if (usingIPv4()) {
                return 1252;
            }
            else {
                return 1232;
            }
        }
    }

    @Override
    public void close() {
        immediateClose();
        // Because this method is not called in the context of processing received messages,
        // sender flush must be called explicitly.
        getSender().flush();
    }

    @Override
    public void closeAndWait() {
        // After 3 PTO, connection should have been terminated anyway, so no use in waiting longer.
        closeAndWait(Duration.ofMillis(4L * getSender().getPto()));
    }

    @Override
    public void closeAndWait(Duration maxWait) {
        close();

        long maxWaitMillis = Long.min(maxWait.toMillis(), 4L * getSender().getPto());
        long waitedMillis = 0;

        try {
            // Busy wait is not ideal, but this method will only be used by a client that is waiting to shutdown JVM, so don't bother.
            while (connectionState != Status.Closed && waitedMillis < maxWaitMillis) {
                Thread.sleep(1);
                waitedMillis++;
            }
        } catch (InterruptedException e) {}
    }

    @Override
    public void close(QuicConstants.TransportErrorCode applicationError, String errorReason) {
        immediateCloseWithError(applicationError.value, QUIC_LAYER_ERROR, errorReason);
        // Because this method is not called in the context of processing received messages,
        // sender flush must be called explicitly.
        getSender().flush();
    }

    @Override
    public void close(long applicationError, String errorReason) {
        immediateCloseWithError(applicationError, APPLICATION_ERROR, errorReason);
        // Because this method is not called in the context of processing received messages,
        // sender flush must be called explicitly.
        getSender().flush();
    }

    private void schedule(Runnable command, int delay, TimeUnit unit) {
        try {
            scheduler.schedule(command, delay, unit);
        }
        catch (RejectedExecutionException rejected) {
            // Can happen when already terminated; don't bother
        }
    }

    @Override
    public Statistics getStats() {
        return new Statistics(getSender().getStatistics());
    }

    @Override
    public QuicVersion getQuicVersion() {
        return quicVersion.getVersion().toQuicVersion();
    }

    @Override
    public void setConnectionListener(ConnectionListener connectionListener) {
        this.connectionListener = connectionListener;
    }

    protected abstract boolean usingIPv4();

    protected abstract PacketFilter createProcessorChain();
    
    protected abstract SenderImpl getSender();

    protected abstract TlsEngine getTlsEngine();

    protected abstract GlobalAckGenerator getAckGenerator();

    protected abstract StreamManager getStreamManager();

    protected abstract ConnectionIdManager getConnectionIdManager();

    @Deprecated
    public abstract long getInitialMaxStreamData();

    public abstract int getMaxShortHeaderPacketOverhead();

    /**
     * Returns the connection ID of this connection. During handshake, this is a fixed ID, that is generated by this
     * endpoint. After handshaking, this is one of the active connection ID's; if there are multiple active connection
     * ID's, which one is returned is not determined (but this method should always return the same until it is not
     * active anymore). Note that after handshaking, the connection ID (of this endpoint) is not used for sending
     * packets (short header packets only contain the destination connection ID), only for routing received packets.
     * @return
     */
    public abstract byte[] getSourceConnectionId();

    /**
     * Returns the current peer connection ID, i.e. the connection ID this endpoint uses as destination connection id
     * when sending packets.
     * During handshake this is a fixed ID generated by the peer (except for the first Initial packets send by the client).
     * After handshaking, there can be multiple active connection ID's supplied by the peer; which one is current (thus,
     * is being used when sending packets) is determined by the implementation.
     * @return
     */
    public abstract byte[] getDestinationConnectionId();

    public IdleTimer getIdleTimer() {
        return idleTimer;
    }

    public Role getRole() {
        return role;
    }

    public PacketFilter getPacketProcessorChain() {
        return processorChain;
    }

    public void addAckFrameReceivedListener(FrameReceivedListener<AckFrame> recoveryManager) {
        this.recoveryManager = recoveryManager;
    }

    public void enableDatagramExtension() {
        if (datagramExtensionStatus != DatagramExtensionStatus.Disabled) {
            throw new IllegalStateException("Datagram extension can only be disable once and before connection is established.");
        }
        if (datagramExtensionStatus == DatagramExtensionStatus.Disabled) {
            datagramExtensionStatus = DatagramExtensionStatus.Enable;
        }
    }

    protected class CheckDestinationFilter extends BasePacketFilter {

        public CheckDestinationFilter(PacketFilter next) {
            super(next);
        }

        @Override
        public void processPacket(QuicPacket packet, PacketMetaData metaData) {
            if (checkDestinationConnectionId(packet)) {
                next(packet, metaData);
            }
            else {
                discard(packet, "with unknown destination connection ID");
            }
        }
    }

    protected class ClosingOrDrainingFilter extends BasePacketFilter {

        public ClosingOrDrainingFilter(PacketFilter next, Logger log) {
            super(next, log);
        }

        @Override
        public void processPacket(QuicPacket packet, PacketMetaData metaData) {
            if (connectionState.closingOrDraining()) {
                if (connectionState.isClosing()) {
                    // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2.1
                    // "An endpoint in the closing state sends a packet containing a CONNECTION_CLOSE frame in response
                    //  to any incoming packet that it attributes to the connection."
                    handlePacketInClosingState(packet);
                }
                else {
                    discard(packet, "in draining state");
                }
            }
            else {
                next(packet, metaData);
            }
        }
    }

    protected class PostProcessingFilter extends BasePacketFilter {

            public PostProcessingFilter(PacketFilter next) {
                super(next);
            }

            @Override
            public void processPacket(QuicPacket packet, PacketMetaData metaData) {
                next(packet, metaData);
                getSender().packetProcessed(metaData.moreDataInDatagram());
            }
    }
}
