/*
 * Copyright © 2019 Peter Doornbosch
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

import net.luminis.tls.ByteUtils;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class ShortHeaderPacket extends QuicPacket {

    private byte[] destinationConnectionId;
    private byte[] packetBytes;

    /**
     * Constructs an empty short header packet for use with the parse() method.
     * @param quicVersion
     */
    public ShortHeaderPacket(Version quicVersion) {
        this.quicVersion = quicVersion;
    }

    /**
     * Constructs a short header packet for sending (client role).
     * @param quicVersion
     * @param destinationConnectionId
     * @param frame
     */
    public ShortHeaderPacket(Version quicVersion, byte[] destinationConnectionId, QuicFrame frame) {
        this.quicVersion = quicVersion;
        this.destinationConnectionId = destinationConnectionId;
        frames = new ArrayList<>();
        if (frame != null) {
            frames.add(frame);
        }
    }

    public ShortHeaderPacket parse(ByteBuffer buffer, QuicConnection connection, ConnectionSecrets connectionSecrets, long largestPacketNumber, Logger log) throws MissingKeysException {
        int startPosition = buffer.position();
        log.debug("Parsing " + this.getClass().getSimpleName());
        byte flags = buffer.get();
        checkPacketType(flags);

        byte[] sourceConnectionId = connection.getSourceConnectionId();
        byte[] packetConnectionId = new byte[sourceConnectionId.length];
        destinationConnectionId = packetConnectionId;
        buffer.get(packetConnectionId);
        log.debug("Destination connection id", packetConnectionId);

        NodeSecrets serverSecrets = connectionSecrets.getServerSecrets(getEncryptionLevel());
        if (serverSecrets == null) {
            // Could happen when, due to packet reordering, the first short header packet arrives before handshake is finished.
            // https://tools.ietf.org/html/draft-ietf-quic-tls-18#section-5.7
            // "Due to reordering and loss, protected packets might be received by an
            //   endpoint before the final TLS handshake messages are received."
            throw new MissingKeysException("Missing application keys");
        }
        parsePacketNumberAndPayload(buffer, flags, buffer.limit() - buffer.position(), serverSecrets, largestPacketNumber, log);

        packetSize = buffer.position() - startPosition;
        return this;
    }

    protected EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.App;
    }

    @Override
    public byte[] generatePacketBytes(long packetNumber, ConnectionSecrets connectionSecrets) {
        this.packetNumber = packetNumber;
        NodeSecrets clientSecrets = connectionSecrets.getClientSecrets(getEncryptionLevel());

        ByteBuffer buffer = ByteBuffer.allocate(MAX_PACKET_SIZE);
        byte flags;
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.3
        // "|0|1|S|R|R|K|P P|"
        // "Spin Bit (S):  The sixth bit (0x20) of byte 0 is the Latency Spin
        //      Bit, set as described in [SPIN]."
        // "Reserved Bits (R):  The next two bits (those with a mask of 0x18) of
        //      byte 0 are reserved. (...) The value included prior to protection MUST be set to 0. "
        flags = 0x40;  // 0100 0000
        flags = encodePacketNumberLength(flags, packetNumber);
        buffer.put(flags);
        buffer.put(destinationConnectionId);

        byte[] encodedPacketNumber = encodePacketNumber(packetNumber);
        buffer.put(encodedPacketNumber);

        ByteBuffer frameBytes = ByteBuffer.allocate(MAX_PACKET_SIZE);
        frames.stream().forEachOrdered(frame -> frameBytes.put(frame.getBytes()));
        frameBytes.flip();

        protectPacketNumberAndPayload(buffer, encodedPacketNumber.length, frameBytes, 0, clientSecrets);

        buffer.limit(buffer.position());
        packetSize = buffer.limit();
        packetBytes = new byte[packetSize];
        buffer.rewind();
        buffer.get(packetBytes);

        packetSize = packetBytes.length;

        return packetBytes;
    }

    @Override
    public void accept(PacketProcessor processor, Instant time) {
        processor.process(this, time);
    }

    protected void checkPacketType(byte flags) {
        if ((flags & 0x80) != 0x00) {
            // Programming error: this method shouldn't have been called if packet is not a Short Frame
            throw new RuntimeException();
        }
    }

    public byte[] getDestinationConnectionId() {
        return destinationConnectionId;
    }

    @Override
    public String toString() {
        return "Packet "
                + getEncryptionLevel().name().charAt(0) + "|"
                + (packetNumber >= 0? packetNumber: ".") + "|"
                + "S" + "|"
                + ByteUtils.bytesToHex(destinationConnectionId) + "|"
                + packetSize + "|"
                + frames.size() + "  "
                + frames.stream().map(f -> f.toString()).collect(Collectors.joining(" "));
    }

}
