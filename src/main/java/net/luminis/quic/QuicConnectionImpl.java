/*
 * Copyright © 2019, 2020 Peter Doornbosch
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
import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.frame.FrameProcessor3;
import net.luminis.quic.frame.MaxDataFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.*;
import net.luminis.quic.recovery.RecoveryManager;
import net.luminis.quic.send.Sender;
import net.luminis.tls.handshake.TlsEngine;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

import static net.luminis.quic.EncryptionLevel.App;
import static net.luminis.tls.util.ByteUtils.bytesToHex;


public abstract class QuicConnectionImpl implements FrameProcessorRegistry<AckFrame>, PacketProcessor, FrameProcessor3 {

    protected final Version quicVersion;
    protected final Logger log;

    protected final ConnectionSecrets connectionSecrets;
    protected volatile TransportParameters transportParams;
    protected List<HandshakeStateListener> handshakeStateListeners = new CopyOnWriteArrayList<>();
    protected IdleTimer idleTimer;
    protected final List<Runnable> postProcessingActions = new ArrayList<>();
    protected final List<CryptoStream> cryptoStreams = new ArrayList<>();

    protected long flowControlMax;
    protected long flowControlLastAdvertised;
    protected long flowControlIncrement;
    protected long largestPacketNumber;


    protected QuicConnectionImpl(Version quicVersion, Role role, Path secretsFile, Logger log) {
        this.quicVersion = quicVersion;
        this.log = log;

        connectionSecrets = new ConnectionSecrets(quicVersion, role, secretsFile, log);

        transportParams = new TransportParameters(60, 250_000, 3 , 3);
        flowControlMax = transportParams.getInitialMaxData();
        flowControlLastAdvertised = flowControlMax;
        flowControlIncrement = flowControlMax / 10;
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
                log.error("Discarding packet (" + data.position() + " bytes) that cannot be decrypted (" + cannotParse + ")");
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

    QuicPacket parsePacket(ByteBuffer data) throws MissingKeysException, DecryptionException, InvalidPacketException {
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

    private void processPacket(Instant timeReceived, QuicPacket packet) {
        packet.accept(this, timeReceived);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-13.1
        // "A packet MUST NOT be acknowledged until packet protection has been
        //   successfully removed and all frames contained in the packet have been
        //   processed."
        getAckGenerator().packetReceived(packet);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
        // "An endpoint restarts its idle timer when a packet from its peer is received and processed successfully."
        idleTimer.packetProcessed();
    }

    protected CryptoStream getCryptoStream(EncryptionLevel encryptionLevel) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-19.6
        // "There is a separate flow of cryptographic handshake data in each
        //   encryption level"
        if (cryptoStreams.size() <= encryptionLevel.ordinal()) {
            for (int i = encryptionLevel.ordinal() - cryptoStreams.size(); i >= 0; i--) {
                cryptoStreams.add(new CryptoStream(quicVersion, encryptionLevel, connectionSecrets, getTlsEngine(), log, getSender()));
            }
        }
        return cryptoStreams.get(encryptionLevel.ordinal());
    }

    void silentlyCloseConnection(long idleTime) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-10.2
        // "If the idle timeout is enabled by either peer, a connection is
        //   silently closed and its state is discarded when it remains idle for
        //   longer than the minimum of the max_idle_timeouts (see Section 18.2)
        //   and three times the current Probe Timeout (PTO)."
        log.info("Idle timeout: silently closing connection after " + idleTime + " ms of inactivity (" + bytesToHex(getSourceConnectionId()) + ")");
        abortConnection(null);
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

    protected abstract Sender getSender();

    protected abstract TlsEngine getTlsEngine();

    protected abstract GlobalAckGenerator getAckGenerator();

    public abstract long getInitialMaxStreamData();

    public abstract int getMaxShortHeaderPacketOverhead();

    public abstract byte[] getSourceConnectionId();

    public abstract byte[] getDestinationConnectionId();

    public IdleTimer getIdleTimer() {
        return idleTimer;
    }

    

}
