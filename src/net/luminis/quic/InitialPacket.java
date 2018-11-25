package net.luminis.quic;

public class InitialPacket extends LongHeaderPacket {

    public InitialPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, int packetNumber, byte[] payload, ConnectionSecrets connectionSecrets) {
        super(quicVersion, sourceConnectionId, destConnectionId, packetNumber, payload, connectionSecrets);
    }

    protected void generateAdditionalFields() {
        // Token length (variable-length integer)
        packetBuffer.put((byte) 0x00);
    }
}
