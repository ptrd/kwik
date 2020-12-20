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
package net.luminis.quic.qlog;

import net.luminis.quic.frame.*;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.tls.util.ByteUtils;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonReader;
import javax.json.stream.JsonGenerator;
import java.io.StringReader;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

public class FrameFormatter implements FrameProcessor3 {

    private final JsonGenerator jsonGenerator;


    public FrameFormatter(JsonGenerator jsonGenerator) {
        this.jsonGenerator = jsonGenerator;
    }

    @Override
    public void process(QuicFrame frame, QuicPacket packet, Instant timeReceived) {
        String type = frame.getClass().getSimpleName().replace("Frame", "").toLowerCase();
        jsonGenerator.writeStartObject().write("frame_type", type).writeEnd();
    }

    @Override
    public void process(AckFrame ackFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "ack")
                .writeStartArray("acked_ranges")
                .writeStartArray();
        List<Long> ackedPacketNumbers = ackFrame.getAckedPacketNumbers().stream().sorted().collect(Collectors.toList());
        boolean started = false;
        long previousAdded = -1;
        for (long ackedPacketNumber: ackedPacketNumbers) {
            if (ackedPacketNumber != previousAdded + 1) {
                if (! started) {
                    jsonGenerator.write(ackedPacketNumber);
                    started = true;
                }
                else {
                    jsonGenerator.write(previousAdded)
                            .writeEnd()
                            .writeStartArray()
                            .write(ackedPacketNumber);
                }
            }
            previousAdded = ackedPacketNumber;
        }
        jsonGenerator.write(previousAdded)
                .writeEnd()
                .writeEnd()
                .writeEnd();
    }

    @Override
    public void process(ConnectionCloseFrame connectionCloseFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "connection_close")
                .write("raw_error_code", connectionCloseFrame.getErrorCode())
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
    public void process(PathChallengeFrame pathChallengeFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject().write("frame_type", "path_challenge").writeEnd();
    }

    @Override
    public void process(RetireConnectionIdFrame retireConnectionIdFrame, QuicPacket packet, Instant timeReceived) {
        jsonGenerator.writeStartObject()
                .write("frame_type", "retire_connection_id")
                .write("sequence_number", retireConnectionIdFrame.getSequenceNr())
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

    private String format(byte[] data) {
        return ByteUtils.bytesToHex(data);
    }
}
