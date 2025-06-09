/*
 * Copyright © 2025 Peter Doornbosch
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

import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;

import java.nio.ByteBuffer;

/**
 * A composite frame that combines two frames that should be sent together.
 */
public class CompositeFrame extends QuicFrame {

    private final QuicFrame frame1;
    private final QuicFrame frame2;

    public CompositeFrame(QuicFrame frame1, QuicFrame frame2) {
        this.frame1 = frame1;
        this.frame2 = frame2;
    }

    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        throw new UnsupportedOperationException("CompositeFrame does not support accept method directly. Use individual frames instead.");
    }

    @Override
    public int getFrameLength() {
        return frame1.getFrameLength() + frame2.getFrameLength();
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        frame1.serialize(buffer);
        frame2.serialize(buffer);
    }

    @Override
    public String toString() {
        return frame1.toString() + ", " + frame2.toString();
    }
}
