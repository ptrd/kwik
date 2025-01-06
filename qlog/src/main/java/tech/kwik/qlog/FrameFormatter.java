/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.qlog;

import jakarta.json.stream.JsonGenerator;
import tech.kwik.core.frame.*;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.util.Bytes;

import java.time.Instant;
import java.util.ListIterator;

public class FrameFormatter implements FrameProcessor {

    private final JsonGenerator jsonGenerator;


    public FrameFormatter(JsonGenerator jsonGenerator) {
        this.jsonGenerator = jsonGenerator;
    }

    @Override
    public void process(AckFrame ackFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "ack")
                .writeStartArray("acked_ranges");
        ListIterator<Range> rangeIterator = ackFrame.getAcknowledgedRanges().listIterator(ackFrame.getAcknowledgedRanges().size());
        while (rangeIterator.hasPrevious()) {
            Range range = rangeIterator.previous();
                jsonGenerator.writeStartArray()
                        .write(range.getSmallest())
                        .write(range.getLargest())
                        .writeEnd();
        }
        jsonGenerator.writeEnd()
                .writeEnd();
    }

    @Override
    public void process(ConnectionCloseFrame connectionCloseFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "connection_close")
                .write("error_code", connectionCloseFrame.getErrorCode())
                .writeEnd();
    }

    @Override
    public void process(CryptoFrame cryptoFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "crypto")
                .write("offset", cryptoFrame.getOffset())
                .write("length", cryptoFrame.getLength())
                .writeEnd();
    }

    @Override
    public void process(DataBlockedFrame dataBlockedFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject().write("frame_type", "data_blocked").writeEnd();
    }

    @Override
    public void process(DatagramFrame datagramFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject().write("frame_type", "datagram").writeEnd();
    }

    @Override
    public void process(HandshakeDoneFrame handshakeDoneFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject().write("frame_type", "handshake_done").writeEnd();
    }

    @Override
    public void process(MaxDataFrame maxDataFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "max_data")
                .write("maximum", maxDataFrame.getMaxData())
                .writeEnd();
    }

    @Override
    public void process(MaxStreamDataFrame maxStreamDataFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "max_stream_data")
                .write("stream_id", maxStreamDataFrame.getStreamId())
                .write("maximum", maxStreamDataFrame.getMaxData())
                .writeEnd();
    }

    @Override
    public void process(MaxStreamsFrame maxStreamsFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "max_streams")
                .write("stream_type", maxStreamsFrame.isAppliesToBidirectional()? "bidirectional": "unidirectional")
                .write("maximum", maxStreamsFrame.getMaxStreams())
                .writeEnd();
    }

    @Override
    public void process(NewConnectionIdFrame newConnectionIdFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "new_connection_id")
                .write("sequence_number", newConnectionIdFrame.getSequenceNr())
                .write("retire_prior_to", newConnectionIdFrame.getRetirePriorTo())
                .write("connection_id", format(newConnectionIdFrame.getConnectionId()))
                .writeEnd();
    }

    @Override
    public void process(NewTokenFrame newTokenFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "new_token")
                .write("token", format(newTokenFrame.getToken()))
                .writeEnd();
    }

    @Override
    public void process(Padding paddingFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject().write("frame_type", "padding").writeEnd();
    }

    @Override
    public void process(PathChallengeFrame pathChallengeFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject().write("frame_type", "path_challenge").writeEnd();
    }

    @Override
    public void process(PathResponseFrame pathResponseFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject().write("frame_type", "path_response").writeEnd();
    }

    @Override
    public void process(PingFrame pingFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject().write("frame_type", "ping").writeEnd();
    }

    @Override
    public void process(ResetStreamFrame resetStreamFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "reset_stream")
                .write("stream_id", resetStreamFrame.getStreamId())
                .write("error_code", resetStreamFrame.getErrorCode())
                .write("final_size", resetStreamFrame.getFinalSize())
                .writeEnd();
    }

    @Override
    public void process(RetireConnectionIdFrame retireConnectionIdFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "retire_connection_id")
                .write("sequence_number", retireConnectionIdFrame.getSequenceNr())
                .writeEnd();
    }

    @Override
    public void process(StopSendingFrame stopSendingFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "stop_sending")
                .write("stream_id", stopSendingFrame.getStreamId())
                .write("error_code", stopSendingFrame.getErrorCode())
                .writeEnd();
    }

    @Override
    public void process(StreamFrame streamFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "stream")
                .write("stream_id", streamFrame.getStreamId())
                .write("offset", streamFrame.getOffset())
                .write("length", streamFrame.getLength())
                .write("fin", streamFrame.isFinal())
                .writeEnd();
    }

    @Override
    public void process(StreamDataBlockedFrame streamDataBlockedFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "stream_data_blocked")
                .write("stream_id", streamDataBlockedFrame.getStreamId())
                .write("limit", streamDataBlockedFrame.getStreamDataLimit())
                .writeEnd();
    }

    @Override
    public void process(StreamsBlockedFrame streamsBlockedFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "streams_blocked")
                .write("stream_type", streamsBlockedFrame.isBidirectional()? "bidirectional": "unidirectional")
                .write("limit", streamsBlockedFrame.getStreamLimit())
                .writeEnd();
    }

    private String format(byte[] data) {
        return Bytes.bytesToHex(data);
    }
}
