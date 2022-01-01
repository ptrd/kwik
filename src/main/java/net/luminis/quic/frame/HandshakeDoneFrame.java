/*
 * Copyright © 2020, 2021, 2022 Peter Doornbosch
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

import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * https://tools.ietf.org/html/draft-ietf-quic-transport-25#section-19.20
 */
public class HandshakeDoneFrame extends QuicFrame {

    public HandshakeDoneFrame(Version quicVersion) {
    }

    public HandshakeDoneFrame parse(ByteBuffer buffer, Logger log) {
        byte frameType = buffer.get();
        if (frameType != 0x1e) {
            throw new RuntimeException();  // Would be a programming error.
        }

        return this;
    }

    @Override
    public int getFrameLength() {
        return 1;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x1e);
    }

    @Override
    public String toString() {
        return "HandshakeDoneFrame[]";
    }

    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}

