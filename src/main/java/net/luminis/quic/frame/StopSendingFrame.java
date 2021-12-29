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
import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Represents a stop sending frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames
 */
public class StopSendingFrame extends QuicFrame {

    private int streamId;
    private long errorCode;

    public StopSendingFrame(Version quicVersion) {
    }

    public StopSendingFrame(Version quicVersion, Integer streamId, Long errorCode) {
        this.streamId = streamId;
        this.errorCode = errorCode;
    }

    public StopSendingFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        buffer.get();

        streamId = VariableLengthInteger.parse(buffer);
        errorCode = VariableLengthInteger.parseLong(buffer);

        return this;
    }

    @Override
    public int getFrameLength() {
        return 1 + VariableLengthInteger.bytesNeeded(streamId)
                + VariableLengthInteger.bytesNeeded(errorCode);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x05);
        VariableLengthInteger.encode(streamId, buffer);
        VariableLengthInteger.encode(errorCode, buffer);
    }

    @Override
    public String toString() {
        return "StopSendingFrame[" + streamId + ":" + errorCode + "]";
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
}
