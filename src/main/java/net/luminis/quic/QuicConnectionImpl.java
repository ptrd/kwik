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

import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.crypto.Keys;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.*;
import net.luminis.quic.recovery.RecoveryManager;
import net.luminis.quic.send.SenderImpl;
import net.luminis.quic.stream.StreamManager;
import net.luminis.quic.util.ProgressivelyIncreasingRateLimiter;
import net.luminis.quic.util.RateLimiter;
import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.alert.ErrorAlert;
import net.luminis.tls.handshake.TlsEngine;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Function;

import static net.luminis.quic.EncryptionLevel.App;
import static net.luminis.quic.EncryptionLevel.Initial;
import static net.luminis.quic.QuicConstants.TransportErrorCode.INTERNAL_ERROR;
import static net.luminis.quic.QuicConstants.TransportErrorCode.NO_ERROR;
import static net.luminis.quic.send.Sender.NO_RETRANSMIT;
import static net.luminis.tls.util.ByteUtils.bytesToHex;


public abstract class QuicConnectionImpl implements QuicConnection, FrameProcessorRegistry<AckFrame>, PacketProcessor, FrameProcessor3 {

    public enum Status {
        Idle,
        Handshaking,
        HandshakeError,
        Connected,
        Closing,
        Draining,
        Closed,
        Error;

        public boolean closingOrDraining() {
            return this == Closing || this == Draining;
        }

        public boolean isClosing() {
            return this == Closing;
        }
    }

    protected final Version quicVersion;
    private final Role role;
    protected final Logger log;

    protected final ConnectionSecrets connectionSecrets;
    protected volatile TransportParameters transportParams;
    protected volatile HandshakeState handshakeState = HandshakeState.Initial;
    protected List<HandshakeStateListener> handshakeStateListeners = new CopyOnWriteArrayList<>();
    protected IdleTimer idleTimer;
    protected final List<Runnable> postProcessingActions = new ArrayList<>();
    protected final List<CryptoStream> cryptoStreams = new ArrayList<>();

    protected long flowControlMax;
    protected long flowControlLastAdvertised;
    protected long flowControlIncrement;
    protected long largestPacketNumber;

    protected volatile Status connectionState;

    private RateLimiter closeFramesSendRateLimiter;


    protected QuicConnectionImpl(Version quicVersion, Role role, Path secretsFile, Logger log) {
        this.quicVersion = quicVersion;
        this.role = role;
        this.log = log;

        connectionSecrets = new ConnectionSecrets(quicVersion, role, secretsFile, log);

        transportParams = new TransportParameters(60, 250_000, 3 , 3);
        flowControlMax = transportParams.getInitialMaxData();
        flowControlLastAdvertised = flowControlMax;
        flowControlIncrement = flowControlMax / 10;

        connectionState = Status.Idle;
        closeFramesSendRateLimiter = new ProgressivelyIncreasingRateLimiter();
    }

    public void addHandshakeStateListener(RecoveryManager recoveryManager) {
        handshakeStateListeners.add(recoveryManager);
    }

    public void updateConnectionFlowControl(int size) {
        flowControlMax += size;
        if (flowControlMax - flowControlLastAdvertised > flowControlIncrement) {
            send(new MaxDataFrame(flowControlMax), f -> {});
            flowControlLastAdvertised = flowControlMax;
        }
    }

    public void send(QuicFrame frame, Consumer<QuicFrame> lostFrameCallback) {
        send(frame, lostFrameCallback, false);
    }

    public void send(QuicFrame frame, Consumer<QuicFrame> lostFrameCallback, boolean flush) {
        getSender().send(frame, App, lostFrameCallback);
        if (flush) {
            getSender().flush();
        }
    }

    public void send(Function<Integer, QuicFrame> frameSupplier, int minimumSize, EncryptionLevel level, Consumer<QuicFrame> lostCallback) {
        getSender().send(frameSupplier, minimumSize, level, lostCallback);
    }

    public void parsePackets(int datagram, Instant timeReceived, ByteBuffer data) {
        while (data.remaining() > 0) {
            try {
                QuicPacket packet = parsePacket(data);

                log.received(timeReceived, datagram, packet);
                log.debug("Parsed packet with size " + data.position() + "; " + data.remaining() + " bytes left.");

                processPacket(timeReceived, packet);
                getSender().packetProcessed(data.hasRemaining());
            }
            catch (DecryptionException | MissingKeysException cannotParse) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-12.2
                // "if decryption fails (...), the receiver (...) MUST attempt to process the remaining packets."
                int nrOfPacketBytes = data.position();
                if (nrOfPacketBytes == 0) {
                    // Nothing could be made out of it, so the whole datagram will be discarded
                    nrOfPacketBytes = data.remaining();
                }
                log.error("Discarding packet (" + nrOfPacketBytes + " bytes) that cannot be decrypted (" + cannotParse + ")");
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
        getSender().packetProcessed(false);

        // Finally, execute actions that need to be executed after all responses and acks are sent.
        postProcessingActions.forEach(action -> action.run());
        postProcessingActions.clear();
    }

    protected QuicPacket parsePacket(ByteBuffer data) throws MissingKeysException, DecryptionException, InvalidPacketException {
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
            Keys keys = connectionSecrets.getPeerSecrets(packet.getEncryptionLevel());
            if (keys == null) {
                // Could happen when, due to packet reordering, the first short header packet arrives before handshake is finished.
                // https://tools.ietf.org/html/draft-ietf-quic-tls-18#section-5.7
                // "Due to reordering and loss, protected packets might be received by an
                //   endpoint before the final TLS handshake messages are received."
                throw new MissingKeysException(packet.getEncryptionLevel());
            }
            packet.parse(data, keys, largestPacketNumber, log, getSourceConnectionIdLength());
        }
        else {
            packet.parse(data, null, largestPacketNumber, log, 0);
        }

        if (packet.getPacketNumber() != null && packet.getPacketNumber() > largestPacketNumber) {
            largestPacketNumber = packet.getPacketNumber();
        }
        return packet;
    }

    protected void processFrames(QuicPacket packet, Instant timeReceived) {
        for (QuicFrame frame: packet.getFrames()) {
            frame.accept(this, packet, timeReceived);
        }
    }

    protected abstract int getSourceConnectionIdLength();

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

    protected void processPacket(Instant timeReceived, QuicPacket packet) {
        log.getQLog().emitPacketReceivedEvent(packet, timeReceived);

        if (! connectionState.closingOrDraining()) {
            ProcessResult result = packet.accept(this, timeReceived);
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
        else if (connectionState.isClosing()) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2.1
            // "An endpoint in the closing state sends a packet containing a CONNECTION_CLOSE frame in response
            //  to any incoming packet that it attributes to the connection."
            handlePacketInClosingState(packet);
        }
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
            log.info("Effective idle timeout is " + idleTimeout);
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
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.1
        // "If a max_idle_timeout is specified by either peer (...), the connection is silently closed and its state is
        //  discarded when it remains idle for longer than the minimum of both peers max_idle_timeout values."
        getStreamManager().abortAll();
        getSender().stop();
        log.info("Idle timeout: silently closing connection after " + idleTime + " ms of inactivity (" + bytesToHex(getSourceConnectionId()) + ")");
        log.getQLog().emitConnectionClosedEvent(Instant.now());
        terminate();
    }

    protected void immediateClose(EncryptionLevel level) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2
        immediateCloseWithError(level, NO_ERROR.value, null);
        log.getQLog().emitConnectionClosedEvent(Instant.now(), NO_ERROR.value, null);
    }

    /**
     * Immediately closes the connection (with or without error) and enters the "closing state".
     * Connection close frame with indicated error (or "NO_ERROR") is send to peer and after 3 x PTO, the closing state
     * is ended and all connection state is discarded.
     * @param level         The level that should be used for sending the connection close frame
     * @param error         The error code, see https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-20.1.
     * @param errorReason
     */
    protected void immediateCloseWithError(EncryptionLevel level, int error, String errorReason) {
        if (connectionState == Status.Closing || connectionState == Status.Draining) {
            log.debug("Immediate close ignored because already closing");
            return;
        }

        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2
        // "An endpoint sends a CONNECTION_CLOSE frame (Section 19.19) to terminate the connection immediately."
        getSender().stop();
        getSender().send(new ConnectionCloseFrame(quicVersion, error, errorReason), level);
        // "After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the closing state;"
        connectionState = Status.Closing;

        getStreamManager().abortAll();

        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2.3
        // "An endpoint that has not established state, such as a server that detects an error in an Initial packet,
        //  does not enter the closing state."
        if (level != Initial) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2
            // "The closing and draining connection states exist to ensure that connections close cleanly and that
            //  delayed or reordered packets are properly discarded. These states SHOULD persist for at least three
            //  times the current Probe Timeout (PTO) interval"
            int pto = getSender().getPto();
            Executors.newScheduledThreadPool(1).schedule(() -> terminate(), 3 * pto, TimeUnit.MILLISECONDS);
        }
        else {
            postProcessingActions.add(() -> terminate());
        }

        log.getQLog().emitConnectionClosedEvent(Instant.now(), error, errorReason);
    }

    protected void handlePacketInClosingState(QuicPacket packet) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2.2
        // "An endpoint MAY enter the draining state from the closing state if it receives a CONNECTION_CLOSE frame,
        //  which indicates that the peer is also closing or draining."
        if (packet.getFrames().stream().filter(frame -> frame instanceof ConnectionCloseFrame).findAny().isPresent()) {
            connectionState = Status.Draining;
        }
        else {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2.1
            // "An endpoint in the closing state sends a packet containing a CONNECTION_CLOSE frame in response to any
            //  incoming packet that it attributes to the connection."
            // "An endpoint SHOULD limit the rate at which it generates packets in the closing state."
            closeFramesSendRateLimiter.execute(() -> send(new ConnectionCloseFrame(quicVersion), NO_RETRANSMIT));
        }
    }

    protected void handlePeerClosing(ConnectionCloseFrame closing) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2.2
        // "The draining state is entered once an endpoint receives a CONNECTION_CLOSE frame, which indicates that its
        //  peer is closing or draining."
        if (!connectionState.closingOrDraining()) {  // Can occur due to race condition (both peers closing simultaneously)
            if (closing.hasError()) {
                log.error("Connection closed by peer with " + determineClosingErrorMessage(closing));
            }
            else {
                log.info("Peer is closing");
            }
            getSender().stop();

            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2.2
            // "An endpoint that receives a CONNECTION_CLOSE frame MAY send a single packet containing a CONNECTION_CLOSE
            //  frame before entering the draining state, using a CONNECTION_CLOSE frame and a NO_ERROR code if appropriate.
            //  An endpoint MUST NOT send further packets."
            send(new ConnectionCloseFrame(quicVersion), NO_RETRANSMIT);

            connectionState = Status.Draining;
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2
            // "The closing and draining connection states exist to ensure that connections close cleanly and that
            //  delayed or reordered packets are properly discarded. These states SHOULD persist for at least three
            //  times the current Probe Timeout (PTO) interval"
            int pto = getSender().getPto();
            Executors.newScheduledThreadPool(1).schedule(() -> terminate(), 3 * pto, TimeUnit.MILLISECONDS);
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
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.2
        // "Once its closing or draining state ends, an endpoint SHOULD discard all connection state."
        idleTimer.shutdown();
        getSender().shutdown();
        connectionState = Status.Closed;
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

    public abstract void abortConnection(Throwable error);

    public static int getMaxPacketSize() {
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

    @Override
    public void close() {
        immediateClose(App);
    }

    @Override
    public Statistics getStats() {
        return new Statistics(getSender().getStatistics());
    }

    protected abstract SenderImpl getSender();

    protected abstract TlsEngine getTlsEngine();

    protected abstract GlobalAckGenerator getAckGenerator();

    protected abstract StreamManager getStreamManager();

    public abstract long getInitialMaxStreamData();

    public abstract int getMaxShortHeaderPacketOverhead();

    public abstract byte[] getSourceConnectionId();

    public abstract byte[] getDestinationConnectionId();

    public IdleTimer getIdleTimer() {
        return idleTimer;
    }

    

}
