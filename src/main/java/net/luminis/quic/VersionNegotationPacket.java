package net.luminis.quic;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Represents a Version Negotiation Packet as specified by
 * https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.4
 */
public class VersionNegotationPacket extends QuicPacket {

    private int packetSize;

    public List<String> getServerSupportedVersions() {
        return serverSupportedVersions;
    }

    List<String> serverSupportedVersions = new ArrayList<>();

    public VersionNegotationPacket parse(ByteBuffer buffer, Logger log) {
        log.debug("Parsing VersionNegotationPacket");
        buffer.get();     // Type

        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.4:
        // "A Version Negotiation packet ... will appear to be a packet using the long header, but
        //  will be identified as a Version Negotiation packet based on the
        //  Version field having a value of 0."
        int zeroVersion = buffer.getInt();
        if (zeroVersion != 0) {
            throw new ImplementationError();
        }

        byte dcilScil = buffer.get();
        int dstConnIdLength = ((dcilScil & 0xf0) >> 4) + 3;
        int srcConnIdLength = (dcilScil & 0x0f) + 3;

        byte[] destConnId = new byte[dstConnIdLength];
        buffer.get(destConnId);
        log.debug("Destination connection id", destConnId);
        byte[] srcConnId = new byte[srcConnIdLength];
        buffer.get(srcConnId);
        log.debug("Source connection id", srcConnId);

        while (buffer.remaining() >= 4) {
            int versionData = buffer.getInt();
            String supportedVersion = parseVersion(versionData);
            if (supportedVersion != null) {
                serverSupportedVersions.add(supportedVersion);
                log.debug("Server supports version " + supportedVersion);
            }
            else {
                serverSupportedVersions.add(String.format("Unknown version %x", versionData));
                log.debug(String.format("Server supports unknown version %x", versionData));
            }
        }

        packetSize = buffer.limit();
        return this;
    }

    private String parseVersion(int versionData) {
        try {
            return Version.parse(versionData).toString();
        } catch (UnknownVersionException e) {
            return null;
        }
    }

    @Override
    protected EncryptionLevel getEncryptionLevel() {
        return null;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public void accept(PacketProcessor processor) {
        processor.process(this);
    }

    @Override
    public String toString() {
        return "Packet "
                + "I" + "|"
                + "-" + "|"
                + "V" + "|"
                + packetSize + "|"
                + "0" + "  "
                + serverSupportedVersions.stream().collect(Collectors.joining(", "));
    }

}
