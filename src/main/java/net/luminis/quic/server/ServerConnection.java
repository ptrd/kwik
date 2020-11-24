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
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.*;
import net.luminis.quic.send.SenderImpl;
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

import static net.luminis.quic.QuicConstants.TransportErrorCode.TRANSPORT_PARAMETER_ERROR;


public class ServerConnection extends QuicConnectionImpl implements TlsStatusEventHandler {

    private final SenderImpl sender;
    private final byte[] scid;
    private final byte[] dcid;
    private final GlobalAckGenerator ackGenerator;
    private List<FrameProcessor2<AckFrame>> ackProcessors = new CopyOnWriteArrayList<>();
    private final TlsServerEngine tlsEngine;
    private final List<String> supportedApplicationLayerProtocols;
    private final byte[] originalDcid;
    private final Consumer<byte[]> closeCallback;

    protected ServerConnection(Version quicVersion, DatagramSocket serverSocket, InetSocketAddress initialClientAddress,
                               byte[] scid, byte[] dcid, byte[] originalDcid, TlsServerEngineFactory tlsServerEngineFactory,
                               Integer initialRtt, Consumer<byte[]> closeCallback, Logger log) {
        super(quicVersion, Role.Server, null, log);
        this.scid = scid;
        this.dcid = dcid;
        this.originalDcid = originalDcid;
        this.closeCallback = closeCallback;

        String supportedProtocol = "hq-" + quicVersion.toString().substring(quicVersion.toString().length() - 2);   // Assuming draft version with 2 digits ;-)
        supportedApplicationLayerProtocols = List.of(supportedProtocol);
        tlsEngine = tlsServerEngineFactory.createServerEngine(new TlsMessageSender(), this);

        idleTimer = new IdleTimer(this, log);
        sender = new SenderImpl(quicVersion, getMaxPacketSize(), serverSocket, initialClientAddress,this, initialRtt, log);
        idleTimer.setPtoSupplier(sender::getPto);

        ackGenerator = sender.getGlobalAckGenerator();
        registerProcessor(ackGenerator);

        connectionSecrets.computeInitialKeys(originalDcid);
        sender.start(connectionSecrets);
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
        return 0;
    }

    @Override
    public int getMaxShortHeaderPacketOverhead() {
        return 0;
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
            Optional<String> applicationProtocol = selectSupportedApplicationProtocol(((ApplicationLayerProtocolNegotiationExtension) alpnExtension.get()).getProtocols());
            applicationProtocol.map(protocol -> {
                // Add negotiated protocol to TLS response (Encrypted Extensions message)
                tlsEngine.addServerExtensions(new ApplicationLayerProtocolNegotiationExtension(protocol));
                return protocol;
            }).orElseThrow(() -> new NoApplicationProtocolAlert());
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

        TransportParameters serverTransportParams = new TransportParameters();
        serverTransportParams.setInitialSourceConnectionId(scid);
        serverTransportParams.setOriginalDestinationConnectionId(originalDcid);
        tlsEngine.addServerExtensions(new QuicTransportParametersExtension(quicVersion, serverTransportParams, Role.Server));
    }

    @Override
    public void process(InitialPacket packet, Instant time) {
        processFrames(packet, time);
    }

    @Override
    public void process(LongHeaderPacket packet, Instant time) {

    }

    @Override
    public void process(ShortHeaderPacket packet, Instant time) {

    }

    @Override
    public void process(VersionNegotiationPacket packet, Instant time) {

    }

    @Override
    public void process(HandshakePacket packet, Instant time) {

    }

    @Override
    public void process(RetryPacket packet, Instant time) {

    }

    @Override
    public void process(QuicFrame frame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(AckFrame ackFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(ConnectionCloseFrame connectionCloseFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(CryptoFrame cryptoFrame, QuicPacket packet, Instant timeReceived) {
        try {
            getCryptoStream(packet.getEncryptionLevel()).add(cryptoFrame);
        } catch (TlsProtocolException e) {
            closeWithError(packet.getEncryptionLevel(), quicError(e), e.getMessage());
        }
    }

    @Override
    public void process(HandshakeDoneFrame handshakeDoneFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(MaxDataFrame maxDataFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(MaxStreamDataFrame maxStreamDataFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(MaxStreamsFrame maxStreamsFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(NewConnectionIdFrame newConnectionIdFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(PathChallengeFrame pathChallengeFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(RetireConnectionIdFrame retireConnectionIdFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    public void process(StreamFrame streamFrame, QuicPacket packet, Instant timeReceived) {

    }

    @Override
    protected void terminate() {
        super.terminate();
        closeCallback.accept(scid);
    }

    private Optional<String> selectSupportedApplicationProtocol(List<String> protocols) {
        Set<String> intersection = new HashSet<String>(supportedApplicationLayerProtocols);
        intersection.retainAll(protocols);
        return intersection.stream().findFirst();
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

        }

        @Override
        public void send(CertificateVerifyMessage cv) throws IOException {

        }

        @Override
        public void send(FinishedMessage finished) throws IOException {

        }
    }

    public boolean isClosed() {
        return connectionState == Status.Closed;
    }

}
