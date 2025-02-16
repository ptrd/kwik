/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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

import tech.kwik.core.generic.InvalidIntegerEncodingException;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Represents a stream data blocked frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-stream_data_blocked-frames
 */
public class StreamDataBlockedFrame extends QuicFrame {

    private int streamId;
    private long streamDataLimit;

    public StreamDataBlockedFrame() {
    }

    public StreamDataBlockedFrame(Version quicVersion, int streamId, long streamDataLimit) {
        this.streamId = streamId;
        this.streamDataLimit = streamDataLimit;
    }

    public StreamDataBlockedFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException, TransportError {
        byte frameType = buffer.get();
        streamId = parseVariableLengthIntegerLimitedToInt(buffer);  // Kwik does not support stream id's larger than max int.
        streamDataLimit = VariableLengthInteger.parseLong(buffer);

        return this;
    }

    @Override
    public int getFrameLength() {
        return 1 + VariableLengthInteger.bytesNeeded(streamId)
                + VariableLengthInteger.bytesNeeded(streamDataLimit);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x15);
        VariableLengthInteger.encode(streamId, buffer);
        VariableLengthInteger.encode(streamDataLimit, buffer);
    }

    public static int getMaxSize(int streamId) {
        return 1 + VariableLengthInteger.bytesNeeded(streamId) + 8;
    }

    @Override
    public String toString() {
        return "StreamDataBlockedFrame[" + streamId + "|" + streamDataLimit + "]";
    }

    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }

    public int getStreamId() {
        return streamId;
    }

    public long getStreamDataLimit() {
        return streamDataLimit;
    }
}
