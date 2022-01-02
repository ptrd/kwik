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
import net.luminis.quic.stream.StreamElement;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Stream;


public class StreamFrame extends QuicFrame implements StreamElement, Comparable<StreamElement> {

    private StreamType streamType;
    private int streamId;
    private long offset;
    private int length;
    private byte[] streamData;
    private boolean isFinal;
    private int frameLength;

    public StreamFrame() {
    }

    public StreamFrame(int streamId, byte[] applicationData, boolean fin) {
        this(Version.getDefault(), streamId, 0, applicationData, 0, applicationData.length, fin);
    }

    public StreamFrame(int streamId, long offset, byte[] applicationData, boolean fin) {
        this(Version.getDefault(), streamId, offset, applicationData, 0, applicationData.length, fin);
    }

    public StreamFrame(Version quicVersion, int streamId, long offset, byte[] applicationData, boolean fin) {
        this(quicVersion, streamId, offset, applicationData, 0, applicationData.length, fin);
    }

    public StreamFrame(int streamId, long offset, byte[] applicationData, int dataOffset, int dataLength, boolean fin) {
        this(Version.getDefault(), streamId, offset, applicationData, dataOffset, dataLength, fin);
    }

    public StreamFrame(Version quicVersion, int streamId, long streamOffset, byte[] applicationData, int dataOffset, int dataLength, boolean fin) {
        streamType = Stream.of(StreamType.values()).filter(t -> t.value == (streamId & 0x03)).findFirst().get();
        this.streamId = streamId;
        this.offset = streamOffset;
        this.streamData = new byte[dataLength];
        // This implementation copies the application data, which would not be necessary if the caller guarantees
        // it will not reuse the data buffer (or at least, the range that is used by this frame) and its content
        // will never change.
        ByteBuffer.wrap(streamData).put(applicationData, dataOffset, dataLength);
        this.length = dataLength;
        isFinal = fin;

        frameLength = 1  // frame type
                + VariableLengthInteger.bytesNeeded(streamId)
                + VariableLengthInteger.bytesNeeded(offset)
                + VariableLengthInteger.bytesNeeded(length)
                + length;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        if (frameLength > buffer.remaining()) {
            throw new IllegalArgumentException();
        }

        byte baseType = (byte) 0x08;
        byte frameType = (byte) (baseType | 0x04 | 0x02 | 0x00);  // OFF-bit, LEN-bit, (no) FIN-bit
        if (isFinal) {
            frameType |= 0x01;
        }
        buffer.put(frameType);
        VariableLengthInteger.encode(streamId, buffer);
        VariableLengthInteger.encode(offset, buffer);
        VariableLengthInteger.encode(length, buffer);
        buffer.put(streamData);
    }

    @Override
    public int getFrameLength() {
        return frameLength;
    }

    public StreamFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        int startPosition = buffer.position();

        int frameType = buffer.get();
        boolean withOffset = ((frameType & 0x04) == 0x04);
        boolean withLength = ((frameType & 0x02) == 0x02);
        isFinal = ((frameType & 0x01) == 0x01);

        streamId = VariableLengthInteger.parse(buffer);
        streamType = Stream.of(StreamType.values()).filter(t -> t.value == (streamId & 0x03)).findFirst().get();

        if (withOffset) {
            offset = VariableLengthInteger.parseLong(buffer);
        }
        if (withLength) {
            length = VariableLengthInteger.parse(buffer);
        }
        else {
            length = buffer.limit() - buffer.position();
        }

        streamData = new byte[length];
        buffer.get(streamData);
        frameLength = buffer.position() - startPosition;

        log.decrypted("Stream data", streamData);

        return this;
    }

    @Override
    public String toString() {
        return "StreamFrame[" + streamId + "(" + streamType.abbrev + ")" + "," + offset + "," + length + (isFinal? ",f": "") + "]";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof StreamFrame)) return false;
        StreamFrame that = (StreamFrame) o;
        return streamId == that.streamId &&
                offset == that.offset &&
                length == that.length &&
                isFinal == that.isFinal &&
                Arrays.equals(streamData, that.streamData);
    }

    @Override
    public int hashCode() {
        return Objects.hash(streamId, offset, length);
    }

    @Override
    public int compareTo(StreamElement other) {
        if (this.offset != other.getOffset()) {
            return Long.compare(this.offset, other.getOffset());
        }
        else {
            return Long.compare(this.length, other.getLength());
        }
    }

    public int getStreamId() {
        return streamId;
    }

    public long getOffset() {
        return offset;
    }

    public int getLength() {
        return length;
    }

    public byte[] getStreamData() {
        return streamData;
    }

    @Override
    public long getUpToOffset() {
        return offset + length;
    }

    public boolean isFinal() {
        return isFinal;
    }

    static public int maxOverhead() {
        return 1  // frame type
        + 4 // stream id
        + 4 // offset
        + 4 // length
        ;
    }

    @Override
    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}
