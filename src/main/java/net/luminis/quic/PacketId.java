package net.luminis.quic;

import java.util.Objects;

public class PacketId {

    private final EncryptionLevel encryptionLevel;
    private final int packetNumber;

    public PacketId(EncryptionLevel encryptionLevel, int packetNumber) {
        this.encryptionLevel = encryptionLevel;
        this.packetNumber = packetNumber;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PacketId packetId = (PacketId) o;
        return packetNumber == packetId.packetNumber &&
                encryptionLevel == packetId.encryptionLevel;
    }

    @Override
    public int hashCode() {
        return Objects.hash(encryptionLevel, packetNumber);
    }

    @Override
    public String toString() {
        return "Packet-id " + encryptionLevel.name().charAt(0) + "|" + packetNumber;
    }
}
