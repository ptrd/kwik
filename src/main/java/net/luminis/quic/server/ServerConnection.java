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
import net.luminis.quic.send.Sender;
import net.luminis.quic.send.SenderImpl;
import net.luminis.tls.NewSessionTicket;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.handshake.*;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;


public class ServerConnection extends QuicConnectionImpl implements TlsStatusEventHandler {

    private final SenderImpl sender;
    private final byte[] scid;
    private final byte[] dcid;
    private final GlobalAckGenerator ackGenerator;
    private List<FrameProcessor2<AckFrame>> ackProcessors = new CopyOnWriteArrayList<>();
    private final TlsServerEngine tlsEngine;


    protected ServerConnection(Version quicVersion, DatagramSocket serverSocket, InetSocketAddress initialClientAddress,
                               byte[] scid, byte[] dcid, TlsServerEngineFactory tlsServerEngineFactory, Integer initialRtt, Logger log) {
        super(quicVersion, Role.Server, null, log);
        this.scid = scid;
        this.dcid = dcid;

        tlsEngine = tlsServerEngineFactory.createServerEngine(new TlsMessageSender(), this);

        idleTimer = new IdleTimer(this, log);
        sender = new SenderImpl(quicVersion, getMaxPacketSize(), serverSocket, initialClientAddress,this, initialRtt, log);
        idleTimer.setPtoSupplier(sender::getPto);

        ackGenerator = sender.getGlobalAckGenerator();
        registerProcessor(ackGenerator);

        connectionSecrets.computeInitialKeys(dcid);
        sender.start(connectionSecrets);
    }

    @Override
    public void abortConnection(Throwable error) {
    }

    @Override
    protected Sender getSender() {
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

    }

    @Override
    public void handshakeFinished() {

    }

    @Override
    public void newSessionTicketReceived(NewSessionTicket ticket) {

    }

    @Override
    public void extensionsReceived(List<Extension> extensions) {
    }

    @Override
    public void process(InitialPacket packet, Instant time) {
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

    private class TlsMessageSender implements ServerMessageSender {
        @Override
        public void send(ServerHello sh) throws IOException {
        }

        @Override
        public void send(EncryptedExtensions ee) throws IOException {
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
}
