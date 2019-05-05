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

import java.nio.ByteBuffer;
import java.time.Instant;

public class MockPacket extends QuicPacket {

    private EncryptionLevel encryptionLevel;
    private String message;

    public MockPacket(int packetNumber, int packetSize, String message) {
        this.packetNumber = packetNumber;
        this.packetSize = packetSize;
        this.encryptionLevel = EncryptionLevel.App;
        this.message = message;
    }

    public MockPacket(int packetNumber, int packetSize, EncryptionLevel encryptionLevel) {
        this.packetNumber = packetNumber;
        this.packetSize = packetSize;
        this.encryptionLevel = encryptionLevel;
        this.message = "";
        this.frames.add(new MaxStreamsFrame());
    }

    public MockPacket(int packetNumber, int packetSize, EncryptionLevel encryptionLevel, QuicFrame frame) {
        this.packetNumber = packetNumber;
        this.packetSize = packetSize;
        this.encryptionLevel = encryptionLevel;
        this.message = "";
        this.frames.add(frame);
    }

    public MockPacket(int packetNumber, int packetSize, EncryptionLevel encryptionLevel, String message) {
        this.packetNumber = packetNumber;
        this.packetSize = packetSize;
        this.encryptionLevel = encryptionLevel;
        this.message = message;
    }

    public MockPacket(int packetNumber, int packetSize, EncryptionLevel encryptionLevel, QuicFrame frame, String message) {
        this.packetNumber = packetNumber;
        this.packetSize = packetSize;
        this.encryptionLevel = encryptionLevel;
        this.frames.add(frame);
        this.message = message;
    }

    @Override
    protected EncryptionLevel getEncryptionLevel() {
        return encryptionLevel;
    }

    @Override
    public byte[] generatePacketBytes(long packetNumber, ConnectionSecrets secrets) {
        ByteBuffer buffer = ByteBuffer.allocate(packetSize);
        buffer.putLong(packetNumber);
        buffer.putInt(encryptionLevel.ordinal());
        return buffer.array();
    }

    @Override
    public boolean isCrypto() {
        return ( encryptionLevel.equals(EncryptionLevel.Initial) || encryptionLevel.equals(EncryptionLevel.Handshake))
                && (frames.size() == 0) || frames.stream().filter(frame -> frame instanceof CryptoFrame).findAny().isPresent();
    }

    @Override
    public QuicPacket copy() {
        return new MockPacket((int) packetNumber, packetSize, encryptionLevel, message);
    }

    @Override
    public void accept(PacketProcessor processor, Instant time) {
    }

    @Override
    public String toString() {
        return "MockPacket [" + message + "]";
    }
}
