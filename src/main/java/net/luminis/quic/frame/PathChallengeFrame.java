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

// https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-19.17
// "Endpoints can use PATH_CHALLENGE frames (type=0x1a) to check
//   reachability to the peer and for path validation during connection
//   migration."
public class PathChallengeFrame extends QuicFrame {

    private byte[] data;

    public PathChallengeFrame(Version quicVersion) {
    }

    public PathChallengeFrame parse(ByteBuffer buffer, Logger log) {
        byte frameType = buffer.get();
        if (frameType != 0x1a) {
            throw new RuntimeException();  // Would be a programming error.
        }

        data = new byte[8];
        buffer.get(data);
        return this;
    }

    @Override
    public byte[] getBytes() {
        byte[] frameBytes = new byte[1 + 8];
        frameBytes[0] = 0x1a;
        System.arraycopy(data, 0, frameBytes, 1, 8);
        return frameBytes;
    }

    public byte[] getData() {
        return data;
    }

    @Override
    public String toString() {
        return "PathChallengeFrame[" + ByteUtils.bytesToHex(data) + "]";
    }

    @Override
    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}

