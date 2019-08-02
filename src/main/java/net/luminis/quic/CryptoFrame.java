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

public class CryptoFrame extends QuicFrame implements Comparable<CryptoFrame> {

    private int offset;
    private int length;
    private byte[] cryptoData;
    private byte[] bytes;

    public CryptoFrame(Version quicVersion, int offset, byte[] payload) {
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

    public CryptoFrame() {
    }

    public CryptoFrame(Version quicVersion, byte[] payload) {
        this(quicVersion, 0, payload);
    }

    public CryptoFrame parse(ByteBuffer buffer, Logger log) {
        log.debug("Parsing Crypto frame");
        buffer.get();

        offset = VariableLengthInteger.parse(buffer);
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

    public byte[] getBytes() {
        return bytes;
    }

    public byte[] getCryptoData() {
        return cryptoData;
    }

    public int getOffset() {
        return offset;
    }

    public int getLength() {
        return length;
    }

    public int getUpToOffset() {
        return offset + length;
    }

    @Override
    public int compareTo(CryptoFrame other) {
        if (this.offset != other.offset) {
            return Integer.compare(this.offset, other.offset);
        }
        else {
            return Integer.compare(this.length, other.length);
        }
    }

}
