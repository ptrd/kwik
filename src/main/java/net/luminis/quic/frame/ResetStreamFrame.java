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
import net.luminis.quic.VariableLengthInteger;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Represents a reset stream frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
 */
public class ResetStreamFrame extends QuicFrame {

    private int streamId;
    private long errorCode;
    private long finalSize;

    /**
     * Returns an upper bound for the size of a frame with the given parameters. A frame created with these parameters
     * will never have a size larger than this upper bound.
     * @param streamId
     * @param errorCode
     * @return
     */
    public static int getMaximumFrameSize(int streamId, long errorCode) {
        int maxFinalSizeLength = 8;
        return 1 + VariableLengthInteger.bytesNeeded(streamId) + VariableLengthInteger.bytesNeeded(errorCode) + maxFinalSizeLength;
    }

    public ResetStreamFrame() {}

    public ResetStreamFrame(int streamId, long errorCode, long finalSize) {
        this.streamId = streamId;
        this.errorCode = errorCode;
        this.finalSize = finalSize;
    }

    public ResetStreamFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        byte frameType = buffer.get();
        streamId = VariableLengthInteger.parse(buffer);
        errorCode = VariableLengthInteger.parseLong(buffer);
        finalSize = VariableLengthInteger.parseLong(buffer);
        return this;
    }

    @Override
    public int getFrameLength() {
        return 1 + VariableLengthInteger.bytesNeeded(streamId)
                + VariableLengthInteger.bytesNeeded(errorCode)
                + VariableLengthInteger.bytesNeeded(finalSize);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x04);
        VariableLengthInteger.encode(streamId, buffer);
        VariableLengthInteger.encode(errorCode, buffer);
        VariableLengthInteger.encode(finalSize, buffer);
    }

    @Override
    public String toString() {
        return "ResetStreamFrame[" + streamId + "|" + errorCode + "|" + finalSize + "]";
    }

    @Override
    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }

    public int getStreamId() {
        return streamId;
    }

    public long getErrorCode() {
        return errorCode;
    }

    public long getFinalSize() {
        return finalSize;
    }
}
