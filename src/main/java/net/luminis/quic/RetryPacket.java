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

public class RetryPacket extends QuicPacket {

    private int packetSize;
    private byte[] sourceConnectionId;
    private byte[] destinationConnectionId;
    private byte[] originalDestinationConnectionId;
    private byte[] retryToken;


    public RetryPacket(Version quicVersion) {
    }

    public RetryPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destinationConnectionId, byte[] originalDestinationConnectionId, byte[] retryToken) {
        this.sourceConnectionId = sourceConnectionId;
        this.destinationConnectionId = destinationConnectionId;
        this.originalDestinationConnectionId = originalDestinationConnectionId;
        this.retryToken = retryToken;
    }

    public RetryPacket parse(ByteBuffer buffer, ConnectionSecrets connectionSecrets, Logger log) {
        log.debug("Parsing " + this.getClass().getSimpleName());
        packetSize = buffer.limit();

        byte flags = buffer.get();
        int odcil = (flags & 0x0f);

        try {
            Version quicVersion = Version.parse(buffer.getInt());
        } catch (UnknownVersionException e) {
            // Protocol error: if it gets here, server should match the Quic version we sent
            throw new ProtocolError("Server uses unsupported Quic version");
        }

        byte dcilScil = buffer.get();
        int dstConnIdLength = ((dcilScil & 0xf0) >> 4) + 3;
        int srcConnIdLength = (dcilScil & 0x0f) + 3;

        destinationConnectionId = new byte[dstConnIdLength];
        buffer.get(destinationConnectionId);
        log.debug("Destination connection id", destinationConnectionId);
        sourceConnectionId = new byte[srcConnIdLength];
        buffer.get(sourceConnectionId);
        log.debug("Source connection id", sourceConnectionId);

        originalDestinationConnectionId = new byte[odcil + 3];
        buffer.get(originalDestinationConnectionId);

        int retryTokenLength = buffer.remaining();
        retryToken = new byte[retryTokenLength];
        buffer.get(retryToken);

        return this;
    }

    @Override
    protected EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.Initial;
    }

    @Override
    public void accept(PacketProcessor processor, Instant time) {
        processor.process(this, time);
    }

    @Override
    public byte[] generatePacketBytes(long packetNumber, ConnectionSecrets secrets) {
        return new byte[0];
    }

    @Override
    public boolean canBeAcked() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-17.2.5
        // "A Retry packet does not include a packet number and cannot be explicitly acknowledged by a client."
        return false;
    }

    public byte[] getRetryToken() {
        return retryToken;
    }

    public byte[] getDestinationConnectionId() {
        return destinationConnectionId;
    }

    public byte[] getSourceConnectionId() {
        return sourceConnectionId;
    }

    public byte[] getOriginalDestinationConnectionId() {
        return originalDestinationConnectionId;
    }

    /**/
    @Override
    public String toString() {
        return "Packet "
                + getEncryptionLevel().name().charAt(0) + "|"
                + "-" + "|"
                + "R" + "|"
                + packetSize + "|"
                + " Retry Token (" + retryToken.length + "): " + ByteUtils.bytesToHex(retryToken);
    }
}
