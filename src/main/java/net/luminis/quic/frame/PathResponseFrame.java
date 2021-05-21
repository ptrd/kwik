/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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

import net.luminis.quic.log.Logger;
import net.luminis.quic.Version;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.tls.util.ByteUtils;

import java.nio.ByteBuffer;
import java.time.Instant;

// https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-19.18
// "The PATH_RESPONSE frame (type=0x1b) is sent in response to a
//   PATH_CHALLENGE frame."
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

    @Override
    public byte[] getBytes() {
        byte[] frameBytes = new byte[1 + 8];
        frameBytes[0] = 0x1b;
        System.arraycopy(data, 0, frameBytes, 1, 8);
        return frameBytes;
    }

    public PathResponseFrame parse(ByteBuffer buffer, Logger log) {
        buffer.get();
        data = new byte[8];
        buffer.get(data);
        return this;
    }

    public byte[] getData() {
        return data;
    }

    @Override
    public String toString() {
        return "PathResponseFrame[" + ByteUtils.bytesToHex(data) + "]";
    }

    @Override
    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}
