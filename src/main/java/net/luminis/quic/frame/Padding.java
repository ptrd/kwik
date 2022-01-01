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

import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Represents a number of consecutive padding frames.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-padding-frames
 *
 * Usually, padding will consist of multiple padding frames, each being exactly one (zero) byte. This class can
 * represent an arbitrary number of consecutive padding frames, by recording padding length.
 */
public class Padding extends QuicFrame {

    private int length;

    public Padding() {
    }

    public Padding(int paddingSize) {
        length = paddingSize;
    }

    @Override
    public int getFrameLength() {
        return length;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put(new byte[length]);
    }

    /**
     * Strictly speaking, a padding frame consists of one single byte. For convenience, here all subsequent padding
     * bytes are collected in one padding object.
     * @param buffer
     * @param log
     * @return
     */
    public Padding parse(ByteBuffer buffer, Logger log) {
        byte lastByte = 0;
        while (buffer.position() < buffer.limit() && (lastByte = buffer.get()) == 0)
            length++;

        if (lastByte != 0) {
            // Set back one position
            buffer.position(buffer.position() - 1);
        }

        return this;
    }

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-2
    // "All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered ack-eliciting."
    @Override
    public boolean isAckEliciting() {
        return false;
    }

    @Override
    public String toString() {
        return "Padding(" + length + ")";
    }

    public int getLength() {
        return length;
    }

    @Override
    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}
