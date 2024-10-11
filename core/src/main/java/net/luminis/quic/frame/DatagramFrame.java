/*
 * Copyright © 2024 Peter Doornbosch
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

import net.luminis.quic.generic.InvalidIntegerEncodingException;
import net.luminis.quic.generic.VariableLengthInteger;
import net.luminis.quic.impl.ImplementationError;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.util.Bytes;

import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * RFC 9221   An Unreliable Datagram Extension to QUIC
 * https://www.rfc-editor.org/rfc/rfc9221.html#name-datagram-frame-types
 */
public class DatagramFrame extends QuicFrame {

    public static final int DATAGRAM_FRAME_TYPE_NO_LEN = 0x30;
    public static final int DATAGRAM_FRAME_TYPE_WITH_LEN = 0x31;

    private byte[] data;

    public DatagramFrame(byte[] bytes) {
        this.data = bytes;
    }

    public DatagramFrame() {
    }

    public static int getMaxMinimalFrameSize() {
        return 1 + VariableLengthInteger.bytesNeeded(1500);
    }

    @Override
    public int getFrameLength() {
        return 1 +
                VariableLengthInteger.bytesNeeded(data.length) +
                data.length;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put((byte) DATAGRAM_FRAME_TYPE_WITH_LEN);
        VariableLengthInteger.encode(data.length, buffer);
        buffer.put(data);
    }

    public QuicFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        int frameType = VariableLengthInteger.parse(buffer);
        if (frameType == DATAGRAM_FRAME_TYPE_WITH_LEN) {
            int length = VariableLengthInteger.parse(buffer);
            data = new byte[length];
            buffer.get(data);
        }
        else if (frameType == DATAGRAM_FRAME_TYPE_NO_LEN) {
            data = new byte[buffer.remaining()];
            buffer.get(data);
        }
        else {
            throw new ImplementationError();
        }
        return this;
    }


    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }

    @Override
    public String toString() {
        return "DatagramFrame [" +
                Bytes.bytesToHex(data) +
                ']';
    }

    public byte[] getData() {
        return data;
    }
}
