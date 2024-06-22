/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.core;

import net.luminis.quic.crypto.Aead;
import net.luminis.quic.frame.CryptoFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

public class MockPacket extends QuicPacket {

    private EncryptionLevel encryptionLevel;
    private String message;

    public MockPacket(int packetNumber, int packetSize, String message) {
        this.packetNumber = packetNumber;
        this.packetSize = packetSize;
        this.encryptionLevel = EncryptionLevel.App;
        this.message = message;
        this.frames.add(new StreamFrame(0, message.getBytes(), false));
    }

    public MockPacket(int packetNumber, int packetSize, EncryptionLevel encryptionLevel) {
        this.packetNumber = packetNumber;
        this.packetSize = packetSize;
        this.encryptionLevel = encryptionLevel;
        this.message = "";
        this.frames.add(new StreamFrame(0, "dummy stream frame".getBytes(), false));

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

    public MockPacket(QuicFrame... frames) {
        this.packetNumber = 0;
        this.packetSize = 10 + Stream.of(frames).mapToInt(f -> f.getFrameLength()).sum() + 16;
        this.encryptionLevel = EncryptionLevel.App;
        this.frames.addAll(List.of(frames));
    }

    @Override
    public int estimateLength(int additionalPayload) {
        return packetSize;
    }

    @Override
    public EncryptionLevel getEncryptionLevel() {
        return encryptionLevel;
    }

    @Override
    public PnSpace getPnSpace() {
        switch (encryptionLevel) {
            case Initial: return PnSpace.Initial;
            case Handshake: return PnSpace.Handshake;
            case App: return PnSpace.App;
            default:
                return null;
        }
    }

    @Override
    public byte[] generatePacketBytes(Aead aead) {
        assert(packetNumber >= 0);
        ByteBuffer buffer = ByteBuffer.allocate(Integer.max(12, packetSize));
        buffer.putLong(packetNumber);
        buffer.putInt(encryptionLevel.ordinal());
        return buffer.array();
    }

    @Override
    public void parse(ByteBuffer data, Aead aead, long largestPacketNumber, Logger log, int sourceConnectionIdLength) throws DecryptionException {
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
    public PacketProcessor.ProcessResult accept(PacketProcessor processor, Instant time) {
        return PacketProcessor.ProcessResult.Continue;
    }

    @Override
    public String toString() {
        return "MockPacket [" + message + "]";
    }
}
