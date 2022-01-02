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
package net.luminis.quic.frame;


import net.luminis.quic.InvalidIntegerEncodingException;
import net.luminis.quic.VariableLengthInteger;
import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.stream.StreamElement;

import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Represents a crypto frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-crypto-frames
 */
public class CryptoFrame extends QuicFrame implements StreamElement, Comparable<StreamElement> {

    private long offset;
    private int length;
    private byte[] cryptoData;
    private byte[] bytes;

    public CryptoFrame() {
    }

    public CryptoFrame(Version quicVersion, byte[] payload) {
        this(quicVersion, 0, payload);
    }

    public CryptoFrame(Version quicVersion, long offset, byte[] payload) {
        this.offset = offset;
        cryptoData = payload;
        length = payload.length;
        ByteBuffer frameBuffer = ByteBuffer.allocate(3 * 4 + payload.length);
        VariableLengthInteger.encode(0x06, frameBuffer);
        VariableLengthInteger.encode(offset, frameBuffer);
        VariableLengthInteger.encode(payload.length, frameBuffer);
        frameBuffer.put(payload);

        bytes = new byte[frameBuffer.position()];
        frameBuffer.rewind();
        frameBuffer.get(bytes);
    }

    @Override
    public int getFrameLength() {
        return 1
                + VariableLengthInteger.bytesNeeded(offset)
                + VariableLengthInteger.bytesNeeded(cryptoData.length)
                + cryptoData.length;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x06);
        VariableLengthInteger.encode(offset, buffer);
        VariableLengthInteger.encode(cryptoData.length, buffer);
        buffer.put(cryptoData);
    }

    public CryptoFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        log.debug("Parsing Crypto frame");
        buffer.get();

        offset = VariableLengthInteger.parseLong(buffer);
        length = VariableLengthInteger.parse(buffer);

        cryptoData = new byte[length];
        buffer.get(cryptoData);
        log.decrypted("Crypto data [" + offset + "," + length + "]", cryptoData);

        return this;
    }

    @Override
    public String toString() {
        return "CryptoFrame[" + offset + "," + length + "]";
    }

    public byte[] getStreamData() {
        return cryptoData;
    }

    @Override
    public long getOffset() {
        return offset;
    }

    @Override
    public int getLength() {
        return length;
    }

    @Override
    public long getUpToOffset() {
        return offset + length;
    }

    @Override
    public int compareTo(StreamElement other) {
        if (this.offset != other.getOffset()) {
            return Long.compare(this.offset, other.getOffset());
        }
        else {
            return Long.compare(this.length, other.getLength());
        }
    }

    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}
