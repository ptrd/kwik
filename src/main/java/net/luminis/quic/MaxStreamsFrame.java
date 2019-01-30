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

public class MaxStreamsFrame extends QuicFrame {

    private int maxStreams;

    public MaxStreamsFrame parse(ByteBuffer buffer, Logger log) {
        byte frameType = buffer.get();
        if (frameType != 0x12 && frameType != 0x13) {
            throw new RuntimeException();  // Would be a programming error.
        }

        maxStreams = QuicPacket.parseVariableLengthInteger(buffer);

        return this;
    }

    @Override
    public String toString() {
        return "MaxStreamsFrame[" + maxStreams + "]";
    }

    @Override
    byte[] getBytes() {
        return new byte[0];
    }

}
