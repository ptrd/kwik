/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic.packet;

import net.luminis.quic.*;
import net.luminis.quic.crypto.Keys;
import net.luminis.quic.log.Logger;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

/**
 * Represents a Version Negotiation Packet as specified by
 * https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.4
 */
public class VersionNegotiationPacket extends QuicPacket {

    // Minimal length for a valid packet:  type version dcid len dcid scid len scid version
    private static int MIN_PACKET_LENGTH = 1 +  4 +     1 +      0 +  1 +      0 +  4;
    private static Random random = new Random();

    private byte[] sourceConnectionId;
    private byte[] destinationConnectionId;
    private int packetSize;
    private List<Version> serverSupportedVersions = new ArrayList<>();


    public VersionNegotiationPacket() {
        this(Version.getDefault());
    }

    public VersionNegotiationPacket(Version quicVersion) {
        this.quicVersion = quicVersion;
    }

    public VersionNegotiationPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        serverSupportedVersions = List.of(quicVersion);
        this.sourceConnectionId = sourceConnectionId;
        this.destinationConnectionId = destinationConnectionId;
    }

    public VersionNegotiationPacket(List<Version> supportedVersions, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        serverSupportedVersions = supportedVersions;
        this.sourceConnectionId = sourceConnectionId;
        this.destinationConnectionId = destinationConnectionId;
    }

    public List<Version> getServerSupportedVersions() {
        return serverSupportedVersions;
    }

    @Override
    public void parse(ByteBuffer buffer, Keys keys, long largestPacketNumber, Logger log, int sourceConnectionIdLength) throws DecryptionException, InvalidPacketException {
        log.debug("Parsing VersionNegotationPacket");
        int packetLength = buffer.limit() - buffer.position();
        if (packetLength < MIN_PACKET_LENGTH) {
            throw new InvalidPacketException();
        }
        buffer.get();     // Type

        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.4:
        // "A Version Negotiation packet ... will appear to be a packet using the long header, but
        //  will be identified as a Version Negotiation packet based on the
        //  Version field having a value of 0."
        int zeroVersion = buffer.getInt();
        if (zeroVersion != 0) {
            throw new ImplementationError();
        }

        int dstConnIdLength = buffer.get() & 0xff;
        if (packetLength < MIN_PACKET_LENGTH + dstConnIdLength) {
            throw new InvalidPacketException();
        }
        destinationConnectionId = new byte[dstConnIdLength];
        buffer.get(destinationConnectionId);

        int srcConnIdLength = buffer.get() & 0xff;
        if (packetLength < MIN_PACKET_LENGTH + dstConnIdLength + srcConnIdLength) {
            throw new InvalidPacketException();
        }
        sourceConnectionId = new byte[srcConnIdLength];
        buffer.get(sourceConnectionId);
        log.debug("Destination connection id", destinationConnectionId);
        log.debug("Source connection id", sourceConnectionId);

        while (buffer.remaining() >= 4) {
            int versionData = buffer.getInt();
            Version supportedVersion = parseVersion(versionData);
            if (supportedVersion != null) {
                serverSupportedVersions.add(supportedVersion);
                log.debug("Server supports version " + supportedVersion);
            }
            else {
                log.debug(String.format("Server supports unknown version %x", versionData));
            }
        }

        packetSize = buffer.limit();
    }

    private Version parseVersion(int versionData) {
        try {
            return Version.parse(versionData);
        } catch (UnknownVersionException e) {
            return null;
        }
    }

    @Override
    public EncryptionLevel getEncryptionLevel() {
        return null;
    }

    @Override
    public PnSpace getPnSpace() {
        return null;
    }

    @Override
    public Long getPacketNumber() {
        // Version Negotiation Packet doesn't have a packet number
        return null;
    }

    @Override
    public int estimateLength(int additionalPayload) {
        throw new NotYetImplementedException();
    }


    @Override
    public byte[] generatePacketBytes(Long packetNumber, Keys keys) {
        ByteBuffer buffer = ByteBuffer.allocate(1 + 4 + 1 + destinationConnectionId.length + 1 + sourceConnectionId.length + 4 * serverSupportedVersions.size());

        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2.1
        // "The value in the Unused field is selected randomly by the server. (...)
        //  Servers SHOULD set the most significant bit of this field (0x40) to 1 so that Version Negotiation packets
        //  appear to have the Fixed Bit field."
        buffer.put((byte) ((byte) random.nextInt(256) | 0b11000000));
        // "The Version field of a Version Negotiation packet MUST be set to 0x00000000."
        buffer.putInt(0x00000000);
        buffer.put((byte) destinationConnectionId.length);
        buffer.put(destinationConnectionId);
        buffer.put((byte) sourceConnectionId.length);
        buffer.put(sourceConnectionId);
        serverSupportedVersions.forEach(version -> buffer.put(version.getBytes()));
        return buffer.array();
    }

    @Override
    public PacketProcessor.ProcessResult accept(PacketProcessor processor, Instant time) {
        return processor.process(this, time);
    }

    @Override
    public boolean canBeAcked() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-17.2.1
        // "A Version Negotiation packet cannot be explicitly acknowledged in an ACK frame by a client."
        return false;
    }

    @Override
    public String toString() {
        return "Packet "
                + "V" + "|"
                + "-" + "|"
                + "V" + "|"
                + (packetSize >= 0? packetSize: ".") + "|"
                + "0" + "  "
                + serverSupportedVersions.stream().map(v -> v.toString()).collect(Collectors.joining(", "));
    }

    public byte[] getScid() {
        return sourceConnectionId;
    }

    public byte[] getDcid() {
        return destinationConnectionId;
    }
}
