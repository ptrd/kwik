/*
 * Copyright © 2019, 2020 Peter Doornbosch
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

import net.luminis.quic.InvalidIntegerEncodingException;
import net.luminis.quic.VariableLengthInteger;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.time.Instant;

public class MaxStreamIdFrame extends QuicFrame {

    private int maxStreamId;

    public MaxStreamIdFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        if (buffer.get() != 0x06) {
            throw new RuntimeException();  // Would be a programming error.
        }

        maxStreamId = VariableLengthInteger.parse(buffer);

        return this;
    }

    @Override
    public String toString() {
        return "MaxStreamIdFrame[" + maxStreamId + "]";
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}
