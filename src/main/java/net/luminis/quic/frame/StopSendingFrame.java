/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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

// https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames
// "An endpoint uses a STOP_SENDING frame (type=0x05) to communicate that incoming data is being discarded on receipt
//  per application request. STOP_SENDING requests that a peer cease transmission on a stream."
public class StopSendingFrame extends QuicFrame {

    private int streamId;
    private int errorCode;

    public StopSendingFrame(Version quicVersion) {
    }

    public StopSendingFrame(Version quicVersion, Integer streamId, Integer errorCode) {
        this.streamId = streamId;
        this.errorCode = errorCode;
    }

    @Override
    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(20);
        buffer.put((byte) 0x05);
        VariableLengthInteger.encode(streamId, buffer);
        VariableLengthInteger.encode(errorCode, buffer);

        byte[] frameBytes = new byte[buffer.position()];
        buffer.flip();
        buffer.get(frameBytes);
        return frameBytes;
    }

    public StopSendingFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        buffer.get();

        streamId = VariableLengthInteger.parse(buffer);
        errorCode = VariableLengthInteger.parse(buffer);

        return this;
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

    public int getErrorCode() {
        return errorCode;
    }
}
