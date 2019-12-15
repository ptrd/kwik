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
package net.luminis.quic.frame;

import net.luminis.quic.log.Logger;

import java.nio.ByteBuffer;

// https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-19.1
// The PADDING frame (type=0x00) has no semantic value.
// A PADDING frame has no content.  That is, a PADDING frame consists of
//   the single octet that identifies the frame as a PADDING frame.
public class Padding extends QuicFrame {

    private int length;


    public Padding() {
    }

    public Padding(int paddingSize) {
        length = paddingSize;
    }

    /**
     * Strictly speaking, a padding frame consists of one single byte. For convenience, here all subsequent padding
     * bytes are collected in one padding object.
     * @param buffer
     * @param log
     * @return
     */
    public Padding parse(ByteBuffer buffer, Logger log) {
        while (buffer.position() < buffer.limit() && buffer.get() == 0)
            length++;

        if (buffer.position() < buffer.limit()) {
            // Set back one position
            buffer.position(buffer.position() - 1);
        }

        return this;
    }

    @Override
    public byte[] getBytes() {
        return new byte[length];
    }

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
}
