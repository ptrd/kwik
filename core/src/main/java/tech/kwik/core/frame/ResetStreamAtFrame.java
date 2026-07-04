/*
 * Copyright © 2026 Peter Doornbosch
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

import tech.kwik.core.QuicConstants;
import tech.kwik.core.generic.InvalidIntegerEncodingException;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;

import java.nio.ByteBuffer;

/**
 * Represents a RESET_STREAM_AT frame.
 * https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-07.html
 *
 * RESET_STREAM_AT allows a sender to reset a stream while guaranteeing reliable
 * delivery of the initial bytes up to the reliable size offset.
 */
public class ResetStreamAtFrame extends QuicFrame {

    private int streamId;
    private long errorCode;
    private long finalSize;
    private long reliableSize;

    /**
     * Returns an upper bound for the size of a frame with the given parameters. A frame created with these parameters
     * will never have a size larger than this upper bound.
     * @param streamId
     * @param errorCode
     * @return
     */
    public static int getMaximumFrameSize(int streamId, long errorCode) {
        int maxFinalSizeLength = 8;
        int maxReliableSizeLength = 8;
        return 1 + VariableLengthInteger.bytesNeeded(streamId) + VariableLengthInteger.bytesNeeded(errorCode)
                + maxFinalSizeLength + maxReliableSizeLength;
    }

    public ResetStreamAtFrame() {}

    public ResetStreamAtFrame(int streamId, long errorCode, long finalSize, long reliableSize) {
        this.streamId = streamId;
        this.errorCode = errorCode;
        this.finalSize = finalSize;
        this.reliableSize = reliableSize;
    }

    public ResetStreamAtFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException, TransportError {
        byte frameType = buffer.get();  // 0x24
        streamId = parseVariableLengthIntegerLimitedToInt(buffer);  // Kwik does not support stream id's larger than max int.
        errorCode = VariableLengthInteger.parseLong(buffer);
        finalSize = VariableLengthInteger.parseLong(buffer);
        reliableSize = VariableLengthInteger.parseLong(buffer);

        // https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-07.html#section-4
        // "If the Reliable Size is larger than the Final Size, the receiver MUST close the connection with a
        //  connection error of type FRAME_ENCODING_ERROR."
        if (reliableSize > finalSize) {
            throw new TransportError(QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR,
                    "RESET_STREAM_AT: Reliable Size exceeds Final Size");
        }
        return this;
    }

    @Override
    public int getFrameLength() {
        return 1
                + VariableLengthInteger.bytesNeeded(streamId)
                + VariableLengthInteger.bytesNeeded(errorCode)
                + VariableLengthInteger.bytesNeeded(finalSize)
                + VariableLengthInteger.bytesNeeded(reliableSize);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x24);
        VariableLengthInteger.encode(streamId, buffer);
        VariableLengthInteger.encode(errorCode, buffer);
        VariableLengthInteger.encode(finalSize, buffer);
        VariableLengthInteger.encode(reliableSize, buffer);
    }

    @Override
    public void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }

    @Override
    public String toString() {
        return "ResetStreamAtFrame[" + streamId + "|" + errorCode + "|" + finalSize + "|" + reliableSize + "]";
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

    public long getReliableSize() {
        return reliableSize;
    }
}
