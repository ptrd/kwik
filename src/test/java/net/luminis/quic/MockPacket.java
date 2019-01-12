package net.luminis.quic;

public class MockPacket extends QuicPacket {

    private EncryptionLevel encryptionLevel;
    private int packetSize;
    private String message;

    public MockPacket(int packetNumber, int packetSize, String message) {
        this.packetNumber = packetNumber;
        this.packetSize = packetSize;
        this.encryptionLevel = EncryptionLevel.App;
        this.message = message;
    }

    public MockPacket(int packetNumber, int packetSize, EncryptionLevel encryptionLevel, String message) {
        this.packetNumber = packetNumber;
        this.packetSize = packetSize;
        this.encryptionLevel = encryptionLevel;
        this.message = message;
    }

    @Override
    protected EncryptionLevel getEncryptionLevel() {
        return encryptionLevel;
    }

    @Override
    public byte[] getBytes() {
        return new byte[packetSize];
    }

    @Override
    public void accept(PacketProcessor processor) {
    }

    @Override
    public String toString() {
        return "MockPacket [" + message + "]";
    }
}
