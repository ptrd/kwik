/*
 * Copyright © 2019, 2020, 2025 Peter Doornbosch
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
package tech.kwik.cli;

import tech.kwik.core.frame.FrameProcessor;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.util.Bytes;

import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Generic frame, for sending arbitrary frame data. Sole purpose is to test how implementations respond to invalid or
 * incorrect frames.
 */
public class RawFrame extends QuicFrame {

    private byte[] rawData;

    public RawFrame(byte[] rawData) {
        this.rawData = rawData;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put(rawData);
    }

    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, Instant timeReceived) {
        throw new UnsupportedOperationException("RawFrame cannot be processed");
    }

    @Override
    public int getFrameLength() {
        return rawData.length;
    }

    @Override
    public String toString() {
        return "RawFrame[" + Bytes.bytesToHex(rawData) + "]";
    }
}
