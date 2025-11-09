/*
 * Copyright © 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.packet;

import tech.kwik.core.common.PnSpace;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.crypto.MissingKeysException;
import tech.kwik.core.impl.*;
import tech.kwik.core.log.Logger;

import java.nio.ByteBuffer;
import java.util.function.BiFunction;

public abstract class PacketParser {

    protected ConnectionSecrets connectionSecrets;
    protected VersionHolder quicVersion;
    protected final int cidLength;
    protected PacketFilter processorChain;
    protected Logger log;
    private final Role role;
    protected long[] largestPacketNumber;
    private BiFunction<ByteBuffer, Exception, Boolean> handleUnprotectPacketFailureFunction;


    public PacketParser(ConnectionSecrets secrets, VersionHolder quicVersion, int cidLength, PacketFilter processor, Role role, Logger logger) {
        this(secrets, quicVersion, cidLength, processor, null, role, logger);
    }

    public PacketParser(ConnectionSecrets secrets, VersionHolder quicVersion, int cidLength, PacketFilter processor,
                        BiFunction<ByteBuffer, Exception, Boolean> handleUnprotectPacketFailure, Role role, Logger logger) {
        this.connectionSecrets = secrets;
        this.quicVersion = quicVersion;
        this.cidLength = cidLength;
        processorChain = processor;
        if (handleUnprotectPacketFailure != null) {
            this.handleUnprotectPacketFailureFunction = handleUnprotectPacketFailure;
        }
        else {
            this.handleUnprotectPacketFailureFunction = (data, exception) -> false;
        }

        this.role = role;
        this.log = logger;

        largestPacketNumber = new long[PnSpace.values().length];
    }

    public void parseAndProcessPackets(ByteBuffer data, PacketMetaData metaData) throws TransportError {
        while (data.remaining() > 0) {
            try {
                QuicPacket packet = parsePacket(data);
                log.received(metaData.timeReceived(), metaData.datagramNumber(), packet);
                log.debug("Parsed packet with size " + data.position() + "; " + data.remaining() + " bytes left.");

                processorChain.processPacket(packet, new PacketMetaData(metaData, data.hasRemaining()));
            }
            catch (DecryptionException | MissingKeysException cannotParse) {
                // https://www.rfc-editor.org/rfc/rfc9000.html#name-coalescing-packets
                // "For example, if decryption fails (because the keys are not available or for any other reason), the
                //  receiver MAY either discard or buffer the packet for later processing and MUST attempt to process the
                //  remaining packets."
                int nrOfPacketBytes = data.position();
                if (nrOfPacketBytes == 0) {
                    // Nothing could be made out of it, so the whole datagram will be discarded
                    nrOfPacketBytes = data.remaining();
                }
                if (!handleUnprotectPacketFailureFunction.apply(data, cannotParse)) {
                    if (cannotParse instanceof  MissingKeysException) {
                        if (((MissingKeysException) cannotParse).getMissingKeysCause() != MissingKeysException.Cause.DiscardedKeys) {
                            log.warn("Discarding packet (" + nrOfPacketBytes + " bytes) that cannot be decrypted (" + cannotParse.getMessage() + ")");
                        }
                    }
                    else {
                        log.error("Discarding packet (" + nrOfPacketBytes + " bytes) that cannot be decrypted (" + cannotParse + ")");
                    }
                }
            }
            catch (InvalidPacketException invalidPacket) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-5.2
                // "Invalid packets without packet protection, such as Initial, Retry, or Version Negotiation, MAY be discarded."
                log.debug("Dropping invalid packet");
                // There is no point in trying to parse the rest of the datagram.
                return;
            }

            if (data.position() == 0) {
                // If parsing (or an attempt to parse a) packet does not advance the buffer, there is no point in going on.
                break;
            }

            // Make sure the packet starts at the beginning of the buffer (required by parse routines)
            data = data.slice();
        }
    }

    public QuicPacket parsePacket(ByteBuffer data) throws MissingKeysException, DecryptionException, InvalidPacketException, TransportError {
        data.mark();
        if (data.remaining() < 2) {
            throw new InvalidPacketException("packet too short to be valid QUIC packet");
        }
        byte flags = data.get();

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
            packet = new ShortHeaderPacket(quicVersion.getVersion());
        }
        data.rewind();

        if (packet.getEncryptionLevel() != null) {
            Aead aead = getAead(packet, data);
            long largestPN = packet.getPnSpace() != null? largestPacketNumber[packet.getPnSpace().ordinal()]: 0;
            packet.parse(data, aead, largestPN, log, cidLength);
        }
        else {
            // Packet has no encryption level, i.e. a VersionNegotiationPacket
            packet.parse(data, null, 0, log, 0);
        }

        // Only retry packet and version negotiation packet won't have a packet number.
        if (packet.getPacketNumber() != null && packet.getPacketNumber() > largestPacketNumber[packet.getPnSpace().ordinal()]) {
            largestPacketNumber[packet.getPnSpace().ordinal()] = packet.getPacketNumber();
        }
        return packet;
    }

    protected abstract Aead getAead(QuicPacket packet, ByteBuffer data) throws MissingKeysException, InvalidPacketException, TransportError;

    /**
     * Constructs a (yet empty) long header packet based on the packet flags (first byte).
     * @param flags   first byte of data to parse
     * @param data    data to parse, first byte is already read!
     * @return
     * @throws InvalidPacketException
     */
    private QuicPacket createLongHeaderPacket(byte flags, ByteBuffer data) throws InvalidPacketException {
        final int MIN_LONGHEADERPACKET_LENGTH = 1 + 4 + 1 + 0 + 1 + 0;
        if (1 + data.remaining() < MIN_LONGHEADERPACKET_LENGTH) {
            throw new InvalidPacketException("packet too short to be valid QUIC long header packet");
        }
        int type = (flags & 0x30) >> 4;
        Version packetVersion = new Version(data.getInt());

        // https://www.rfc-editor.org/rfc/rfc9000.html#name-version-negotiation-packet
        // "A Version Negotiation packet is inherently not version specific. Upon receipt by a client, it will be
        // identified as a Version Negotiation packet based on the Version field having a value of 0."
        Version connectionVersion = quicVersion.getVersion();
        if (packetVersion.isZero()) {
            return new VersionNegotiationPacket(connectionVersion);
        }
        else if (InitialPacket.isInitialType(type, packetVersion)) {
            return new InitialPacket(packetVersion);
        }
        else if (RetryPacket.isRetry(type, packetVersion)) {
            return new RetryPacket(connectionVersion);
        }
        else if (HandshakePacket.isHandshake(type, packetVersion)) {
            return new HandshakePacket(connectionVersion);
        }
        else if (ZeroRttPacket.isZeroRTT(type, packetVersion)) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-0-rtt
            // "A 0-RTT packet is used to carry "early" data from the client to the server as part of the first flight,
            //  prior to handshake completion. "
            if (role == Role.Client) {
                // When such a packet arrives, consider it to be caused by network corruption, so
                throw new InvalidPacketException();
            }
            else {
                return new ZeroRttPacket(packetVersion);
            }
        }
        else {
            // Should not happen, all cases should be covered above, but just in case...
            throw new RuntimeException();
        }
    }
}
