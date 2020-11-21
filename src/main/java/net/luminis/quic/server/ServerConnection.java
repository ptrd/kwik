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


public class ServerConnection extends QuicConnectionImpl implements TlsStatusEventHandler {

    private final SenderImpl sender;
    private final byte[] scid;
    private final byte[] dcid;
    private final GlobalAckGenerator ackGenerator;
    private List<FrameProcessor2<AckFrame>> ackProcessors = new CopyOnWriteArrayList<>();
    private final TlsServerEngine tlsEngine;
    private final List<String> supportedApplicationLayerProtocols;
    private final Consumer<byte[]> closeCallback;

    protected ServerConnection(Version quicVersion, DatagramSocket serverSocket, InetSocketAddress initialClientAddress,
                               byte[] scid, byte[] dcid, byte[] originalDcid, TlsServerEngineFactory tlsServerEngineFactory,
                               Integer initialRtt, Consumer<byte[]> closeCallback, Logger log) {
        super(quicVersion, Role.Server, null, log);
        this.scid = scid;
        this.dcid = dcid;
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
        Optional<Extension> alpnExtension = extensions.stream()
                .filter(ext -> ext instanceof ApplicationLayerProtocolNegotiationExtension)
                .findFirst();
        if (alpnExtension.isEmpty()) {
            throw new MissingExtensionAlert();
        }
        else {
            Optional<String> applicationProtocol = selectSupportedApplicationProtocol(((ApplicationLayerProtocolNegotiationExtension) alpnExtension.get()).getProtocols());
            applicationProtocol.map(protocol -> {
                tlsEngine.addServerExtensions(new ApplicationLayerProtocolNegotiationExtension(protocol));
                return protocol;
            }).orElseThrow(() -> new NoApplicationProtocolAlert());
        }
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
