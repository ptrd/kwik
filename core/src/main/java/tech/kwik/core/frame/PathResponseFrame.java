/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.frame;

import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.util.Bytes;

import java.nio.ByteBuffer;

/**
 * Represents a path response frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-path_response-frames
 */
public class PathResponseFrame extends QuicFrame {

    private byte[] data;

    public PathResponseFrame(Version quicVersion, byte[] data) {
        if (data.length != 8) {
            throw new IllegalArgumentException("Path Response Frame must contain 8 bytes data");
        }
        this.data = data;
    }

    public PathResponseFrame(Version quicVersion) {
    }

    public PathResponseFrame parse(ByteBuffer buffer, Logger log) {
        buffer.get();
        data = new byte[8];
        buffer.get(data);
        return this;
    }

    @Override
    public int getFrameLength() {
        return 1 + 8;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x1b);
        buffer.put(data);
    }

    public byte[] getData() {
        return data;
    }

    @Override
    public String toString() {
        return "PathResponseFrame[" + Bytes.bytesToHex(data) + "]";
    }

    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
