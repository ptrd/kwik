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
