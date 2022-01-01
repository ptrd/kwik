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

import net.luminis.quic.InvalidIntegerEncodingException;
import net.luminis.quic.log.Logger;
import net.luminis.quic.VariableLengthInteger;
import net.luminis.quic.Version;
import net.luminis.quic.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Represents a retire connection id frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-retire_connection_id-frames
 */
public class RetireConnectionIdFrame extends QuicFrame {

    private int sequenceNr;

    public RetireConnectionIdFrame(Version quicVersion) {
    }

    public RetireConnectionIdFrame(Version quicVersion, int sequenceNumber) {
        this.sequenceNr = sequenceNumber;
    }

    public RetireConnectionIdFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        buffer.get();
        sequenceNr = VariableLengthInteger.parse(buffer);
        return this;
    }

    @Override
    public int getFrameLength() {
        return 1 + VariableLengthInteger.bytesNeeded(sequenceNr);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x19);
        VariableLengthInteger.encode(sequenceNr, buffer);
    }

    @Override
    public String toString() {
        return "RetireConnectionIdFrame[" + sequenceNr + "]";
    }

    @Override
    public boolean equals(Object obj) {
        return (obj instanceof RetireConnectionIdFrame) &&
                ((RetireConnectionIdFrame) obj).sequenceNr == this.sequenceNr;
    }

    public int getSequenceNr() {
        return sequenceNr;
    }

    @Override
    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}
