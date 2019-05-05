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


// https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-19.14
public class StreamsBlockedFrame extends QuicFrame {

    private boolean bidirectional;
    private int streamLimit;

    public StreamsBlockedFrame parse(ByteBuffer buffer, Logger log) {
        byte frameType = buffer.get();
        bidirectional = frameType == 0x16;
        streamLimit = VariableLengthInteger.parse(buffer);

        return this;
    }

    @Override
    byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public String toString() {
        return "StreamsBlockedFrame[" + (bidirectional? "B": "U") + "|" + streamLimit + "]";
    }
}
