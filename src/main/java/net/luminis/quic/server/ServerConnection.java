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

import net.luminis.quic.*;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.LogProxy;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.*;
import net.luminis.quic.send.SenderImpl;
import net.luminis.quic.stream.FlowControl;
import net.luminis.quic.stream.QuicStream;
import net.luminis.quic.stream.StreamManager;
import net.luminis.quic.tls.QuicTransportParametersExtension;
import net.luminis.tls.NewSessionTicket;
import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.alert.MissingExtensionAlert;
import net.luminis.tls.alert.NoApplicationProtocolAlert;
import net.luminis.tls.extension.ApplicationLayerProtocolNegotiationExtension;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.handshake.*;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

import static net.luminis.quic.QuicConnectionImpl.Status.Connected;
import static net.luminis.quic.QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR;


public class ServerConnection extends QuicConnectionImpl implements TlsStatusEventHandler {

    private final SenderImpl sender;
    private final byte[] scid;
    private final byte[] dcid;
    private final GlobalAckGenerator ackGenerator;
    private final List<FrameProcessor2<AckFrame>> ackProcessors = new CopyOnWriteArrayList<>();
    private final TlsServerEngine tlsEngine;
    private final byte[] originalDcid;
    private final ApplicationProtocolRegistry applicationProtocolRegistry;
    private final Consumer<byte[]> closeCallback;
    private final StreamManager streamManager;
    private final int initialMaxStreamData;
    private final int maxOpenStreamsUni;
    private final int maxOpenStreamsBidi;
    private volatile boolean firstInitialPacketProcessed = false;
    private volatile String negotiatedApplicationProtocol;
    private volatile FlowControl flowController;


    protected ServerConnection(Version quicVersion, DatagramSocket serverSocket, InetSocketAddress initialClientAddress,
                               byte[] scid, byte[] dcid, byte[] originalDcid, TlsServerEngineFactory tlsServerEngineFactory,
                               ApplicationProtocolRegistry applicationProtocolRegistry, Integer initialRtt, Consumer<byte[]> closeCallback, Logger log) {
        super(quicVersion, Role.Server, null, new LogProxy(log, originalDcid));
        this.scid = scid;
        this.dcid = dcid;
        this.originalDcid = originalDcid;
        this.applicationProtocolRegistry = applicationProtocolRegistry;
        this.closeCallback = closeCallback;

        tlsEngine = tlsServerEngineFactory.createServerEngine(new TlsMessageSender(), this);

        idleTimer = new IdleTimer(this, log);
        sender = new SenderImpl(quicVersion, getMaxPacketSize(), serverSocket, initialClientAddress,this, initialRtt, this.log);
        idleTimer.setPtoSupplier(sender::getPto);

        ackGenerator = sender.getGlobalAckGenerator();
        registerProcessor(ackGenerator);

        connectionSecrets.computeInitialKeys(originalDcid);
        sender.start(connectionSecrets);

        initialMaxStreamData = 1_000_000;
        maxOpenStreamsUni = 10;
        maxOpenStreamsBidi = 100;
        streamManager = new StreamManager(this, Role.Server, log, maxOpenStreamsUni, maxOpenStreamsBidi);

        this.log.getQLog().emitConnectionCreatedEvent(Instant.now());
    }

    @Override
    public void abortConnection(Throwable error) {
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
    public long getInitialMaxStreamData() {
        return initialMaxStreamData;
    }

    @Override
    public int getMaxShortHeaderPacketOverhead() {
        return 1  // flag byte
                + dcid.length
                + 4  // max packet number size, in practice this will be mostly 1
                + 16; // encryption overhead
    }

    @Override
    protected int getSourceConnectionIdLength() {
        return scid.length;
    }

    @Override
    public byte[] getSourceConnectionId() {
        return scid;
    }

    @Override
    public byte[] getDestinationConnectionId() {
        return dcid;
    }

    @Override
    public void registerProcessor(FrameProcessor2<AckFrame> ackProcessor) {
        ackProcessors.add(ackProcessor);
    }

    @Override
    public void earlySecretsKnown() {
    }

    @Override
    public void handshakeSecretsKnown() {
        connectionSecrets.computeHandshakeSecrets(tlsEngine, tlsEngine.getSelectedCipher());
    }

    @Override
    public void handshakeFinished() {
        connectionSecrets.computeApplicationSecrets(tlsEngine);
        // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-4.9.2
        // "An endpoint MUST discard its handshake keys when the TLS handshake is confirmed"
        // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-4.1.2
        // "the TLS handshake is considered confirmed at the server when the handshake completes"
        getSender().discard(PnSpace.Handshake, "tls handshake confirmed");
        // TODO: discard keys too
        // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-4.9.2
        // "The server MUST send a HANDSHAKE_DONE frame as soon as it completes the handshake."
        sendHandshakeDone(new HandshakeDoneFrame(quicVersion));
        connectionState = Connected;

        applicationProtocolRegistry.startApplicationProtocolConnection(negotiatedApplicationProtocol, this);
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
            applicationProtocol
                    .map(protocol -> {
                        // Add negotiated protocol to TLS response (Encrypted Extensions message)
                        tlsEngine.addServerExtensions(new ApplicationLayerProtocolNegotiationExtension(protocol));
                        return protocol; })
                    .map(selectedProtocol -> negotiatedApplicationProtocol = selectedProtocol)
                    .orElseThrow(() -> new NoApplicationProtocolAlert());
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
            } catch (TransportError transportParameterError) {
                throw new TlsProtocolException("transport parameter error", transportParameterError);
            }
        }

        TransportParameters serverTransportParams = new TransportParameters(30, initialMaxStreamData, maxOpenStreamsBidi, maxOpenStreamsUni);
        serverTransportParams.setInitialSourceConnectionId(scid);
        serverTransportParams.setOriginalDestinationConnectionId(originalDcid);
        tlsEngine.addServerExtensions(new QuicTransportParametersExtension(quicVersion, serverTransportParams, Role.Server));
    }

    @Override
    public void process(InitialPacket packet, Instant time) {
        if (Arrays.equals(packet.getDestinationConnectionId(), scid) || !firstInitialPacketProcessed) {
            firstInitialPacketProcessed = true;
            processFrames(packet, time);
        }
        else if (Arrays.equals(packet.getDestinationConnectionId(), originalDcid)) {
            // From the specification, it is not clear what to do with packets using the original destination id.
            // It might be that the client did not receive responses, but it might as well be an opportunistic client
            // sending multiple initials at once. Just ignore them; retransmitting will be triggered by detecting lost packets.
            log.debug("Ignoring initial packet with original destination connection id");
        }
        else {
            // Must be programming error
            throw new RuntimeException();
        }
    }

    @Override
    public void process(ShortHeaderPacket packet, Instant time) {
        processFrames(packet, time);
    }

    @Override
    public void process(VersionNegotiationPacket packet, Instant time) {
        // Intentionally discarding packet without any action (clients should not send Version Negotiation packets).
    }

    @Override
    public void process(HandshakePacket packet, Instant time) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2.2.1
        // "A server stops sending and processing Initial packets when it receives its first Handshake packet. "
        sender.discard(PnSpace.Initial, "first handshake packet received");  // Only discards when not yet done.
        processFrames(packet, time);
        // https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-4.9.1
        // "a server MUST discard Initial keys when it first successfully processes a Handshake packet"
        // TODO: discard keys too
    }

    @Override
    public void process(RetryPacket packet, Instant time) {
        // Intentionally discarding packet without any action (clients should not send Retry packets).
    }

    @Override
    public void process(ZeroRttPacket packet, Instant time) {
        // TODO
    }

    @Override
    public void process(QuicFrame frame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(AckFrame ackFrame, QuicPacket packet, Instant timeReceived) {
        ackProcessors.forEach(processor -> processor.process(ackFrame, packet.getPnSpace(), timeReceived));
    }

    @Override
    public void process(ConnectionCloseFrame connectionCloseFrame, QuicPacket packet, Instant timeReceived) {
        handlePeerClosing(connectionCloseFrame);
    }

    @Override
    public void process(CryptoFrame cryptoFrame, QuicPacket packet, Instant timeReceived) {
        try {
            getCryptoStream(packet.getEncryptionLevel()).add(cryptoFrame);
        } catch (TlsProtocolException e) {
            immediateCloseWithError(packet.getEncryptionLevel(), quicError(e), e.getMessage());
        }
    }

    @Override
    public void process(DataBlockedFrame dataBlockedFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(HandshakeDoneFrame handshakeDoneFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(MaxDataFrame maxDataFrame, QuicPacket packet, Instant timeReceived) {
        flowController.process(maxDataFrame);
    }

    @Override
    public void process(MaxStreamDataFrame maxStreamDataFrame, QuicPacket packet, Instant timeReceived) {
        try {
            flowController.process(maxStreamDataFrame);
        }
        catch (TransportError transportError) {
            immediateCloseWithError(EncryptionLevel.App, transportError.getTransportErrorCode().value, null);
        }
    }

    @Override
    public void process(MaxStreamsFrame maxStreamsFrame, QuicPacket packet, Instant timeReceived) {
        streamManager.process(maxStreamsFrame);
    }

    @Override
    public void process(NewConnectionIdFrame newConnectionIdFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(NewTokenFrame newTokenFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(Padding paddingFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(PathChallengeFrame pathChallengeFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(PathResponseFrame pathResponseFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(PingFrame pingFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(ResetStreamFrame resetStreamFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(RetireConnectionIdFrame retireConnectionIdFrame, QuicPacket packet, Instant timeReceived) {

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
    protected void terminate() {
        super.terminate();
        log.getQLog().emitConnectionTerminatedEvent();
        closeCallback.accept(scid);
    }

    private void validateAndProcess(TransportParameters transportParameters) throws TransportError {
        if (transportParameters.getInitialMaxStreamsBidi() > 0x1000000000000000l) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
        if (transportParameters.getMaxUdpPayloadSize() < 1200) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
        if (transportParameters.getAckDelayExponent() > 20) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
        if (transportParameters.getMaxAckDelay() > 16384) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
        if (transportParameters.getActiveConnectionIdLimit() < 2) {
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }
        if (!Arrays.equals(transportParameters.getInitialSourceConnectionId(), dcid)) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-7.3
            // "An endpoint MUST treat absence of the initial_source_connection_id transport parameter from either
            //  endpoint (...) as a connection error of type TRANSPORT_PARAMETER_ERROR."
            // "An endpoint MUST treat the following as a connection error of type TRANSPORT_PARAMETER_ERROR or
            //  PROTOCOL_VIOLATION: a mismatch between values received from a peer in these transport parameters and the
            //  value sent in the corresponding Destination or Source Connection ID fields of Initial packets."
            throw new TransportError(TRANSPORT_PARAMETER_ERROR);
        }

        flowController = new FlowControl(Role.Server, transportParameters.getInitialMaxData(),
                transportParameters.getInitialMaxStreamDataBidiLocal(), transportParameters.getInitialMaxStreamDataBidiRemote(),
                transportParameters.getInitialMaxStreamDataUni(), log);
        streamManager.setFlowController(flowController);
    }

    private class TlsMessageSender implements ServerMessageSender {
        @Override
        public void send(ServerHello sh) {
            getCryptoStream(EncryptionLevel.Initial).write(sh.getBytes());
        }

        @Override
        public void send(EncryptedExtensions ee) {
            getCryptoStream(EncryptionLevel.Handshake).write(ee.getBytes());
        }

        @Override
        public void send(CertificateMessage cm) throws IOException {
            getCryptoStream(EncryptionLevel.Handshake).write(cm.getBytes());
        }

        @Override
        public void send(CertificateVerifyMessage cv) throws IOException {
            getCryptoStream(EncryptionLevel.Handshake).write(cv.getBytes());
        }

        @Override
        public void send(FinishedMessage finished) throws IOException {
            getCryptoStream(EncryptionLevel.Handshake).write(finished.getBytes());
        }
    }

    public boolean isClosed() {
        return connectionState == Status.Closed;
    }

    public byte[] getOriginalDestinationConnectionId() {
        return originalDcid;
    }


    @Override
    public void setMaxAllowedBidirectionalStreams(int max) {

    }

    @Override
    public void setMaxAllowedUnidirectionalStreams(int max) {

    }

    @Override
    public void setDefaultStreamReceiveBufferSize(long size) {

    }

    @Override
    public QuicStream createStream(boolean bidirectional) {
        return streamManager.createStream(bidirectional);
    }

    @Override
    public void setPeerInitiatedStreamCallback(Consumer<QuicStream> streamConsumer) {
        streamManager.setPeerInitiatedStreamCallback(streamConsumer);
    }

}
