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

public class MaxStreamsFrame extends QuicFrame {

    private long maxStreams;
    private boolean appliesToBidirectional;

    public MaxStreamsFrame(long maxStreams, boolean appliesToBidirectional) {
        this.maxStreams = maxStreams;
        this.appliesToBidirectional = appliesToBidirectional;
    }

    public MaxStreamsFrame() {
    }

    public MaxStreamsFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        byte frameType = buffer.get();
        if (frameType != 0x12 && frameType != 0x13) {
            throw new RuntimeException();  // Would be a programming error.
        }

        appliesToBidirectional = frameType == 0x12;
        maxStreams = VariableLengthInteger.parse(buffer);

        return this;
    }

    @Override
    public String toString() {
        return "MaxStreamsFrame["
                + (appliesToBidirectional? "B": "U") + ","
                + maxStreams + "]";
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    public long getMaxStreams() {
        return maxStreams;
    }

    public boolean isAppliesToBidirectional() {
        return appliesToBidirectional;
    }

    @Override
    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}
