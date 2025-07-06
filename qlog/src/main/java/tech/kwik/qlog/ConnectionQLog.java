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

import jakarta.json.Json;
import jakarta.json.stream.JsonGenerator;
import tech.kwik.core.packet.LongHeaderPacket;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.packet.RetryPacket;
import tech.kwik.core.util.Bytes;
import tech.kwik.qlog.event.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static jakarta.json.stream.JsonGenerator.PRETTY_PRINTING;
import static java.util.Collections.emptyMap;


/**
 * Manages (collects and stores) the qlog file for exactly one quic connection.
 * The log is identified by the original destination connection id.
 */
public class ConnectionQLog implements QLogEventProcessor {

    private final byte[] cid;
    private final Instant startTime;
    private final JsonGenerator jsonGenerator;
    private final FrameFormatter frameFormatter;
    private boolean closed;  // thread-confined

    public ConnectionQLog(QLogEvent startEvent) throws IOException {
        this(startEvent, getOutputStream(startEvent.getCid()));
    }

    public ConnectionQLog(QLogEvent event, OutputStream output) throws IOException {
        this.cid = event.getCid();
        this.startTime = event.getTime();

        boolean prettyPrinting = false;
        Map<String, ?> configuration = prettyPrinting ? Map.of(PRETTY_PRINTING, "whatever") : emptyMap();
        jsonGenerator = Json.createGeneratorFactory(configuration).createGenerator(output);

        frameFormatter = new FrameFormatter(jsonGenerator);

        writeHeader();
    }

    @Override
    public void process(PacketSentEvent event) {
        writePacketEvent(event);
    }

    @Override
    public void process(ConnectionCreatedEvent event) {
        // Not used
    }

    @Override
    public void process(ConnectionClosedEvent event) {
        emitConnectionClosedEvent(event);
    }

    @Override
    public void process(PacketReceivedEvent event) {
        writePacketEvent(event);
    }

    @Override
    public void process(ConnectionTerminatedEvent event) {
        close();
    }

    @Override
    public void process(CongestionControlMetricsEvent event) {
        emitMetrics(event);
    }

    @Override
    public void process(RttMetricsEvent event) {
        emitMetrics(event);
    }

    @Override
    public void process(RecoveryMetricsEvent event) {
        emitMetrics(event);
    }

    @Override
    public void process(PacketLostEvent packetLostEvent) {
        writePacketLostEvent(packetLostEvent);
    }

    public void close() {
        if (! closed) {
            closed = true;
            writeFooter();
        }
    }

    private static OutputStream getOutputStream(byte[] cid) throws FileNotFoundException {
        // Buffering not needed on top of output stream, JsonGenerator has its own buffering.
        String qlogDir = System.getenv("QLOGDIR");
        OutputStream output = new FileOutputStream(new File(qlogDir, format(cid, null) + ".qlog"));
        return output;
    }

    private void writeHeader() {
        jsonGenerator.writeStartObject()
                .write("qlog_version", "draft-02")
                .write("qlog_format", "JSON")
                .writeStartArray("traces")
                .writeStartObject()  // start trace
                .writeStartObject("common_fields")
                .write("ODCID", Bytes.bytesToHex(cid))
                .write("time_format", "relative")
                .write("reference_time", startTime.toEpochMilli())
                .writeEnd()
                .writeStartObject("vantage_point")
                .write("name", "kwik")
                .write("type", "server")
                .writeEnd()
                .writeStartArray("events");
    }

    private void writePacketEvent(PacketEvent event) {
        QuicPacket packet = event.getPacket();
        jsonGenerator.writeStartObject()
                .write("time", Duration.between(startTime, event.getTime()).toMillis())
                .write("name", "transport:" + (event instanceof PacketReceivedEvent? "packet_received": "packet_sent"))
                .writeStartObject("data")
                .writeStartObject("header")
                .write("packet_type", formatPacketType(packet))
                .write("packet_number", packet.getPacketNumber() != null? packet.getPacketNumber(): 0)
                .write("dcid", format(packet.getDestinationConnectionId(), ""));
        if (packet instanceof LongHeaderPacket) {
            jsonGenerator.write("scid", format(((LongHeaderPacket) packet).getSourceConnectionId(), ""));
        }
        jsonGenerator.writeEnd();  // header

        jsonGenerator.writeStartArray("frames");
        packet.getFrames().stream().forEach(frame -> frame.accept(frameFormatter, null, null));
        jsonGenerator.writeEnd()  // frames
                .writeStartObject("raw")
                .write("length", packet.getSize())
                .writeEnd()       // raw
                .writeEnd()       // data
                .writeEnd();      // event
    }

    private void writePacketLostEvent(PacketLostEvent event) {
        QuicPacket packet = event.getPacket();
        jsonGenerator.writeStartObject()
                .write("time", Duration.between(startTime, event.getTime()).toMillis())
                .write("name", "recovery:packet_lost")
                .writeStartObject("data")
                .writeStartObject("header")
                .write("packet_type", formatPacketType(packet))
                .write("packet_number", packet.getPacketNumber() != null? packet.getPacketNumber(): 0)
                .writeEnd()  // header
                .writeEnd()       // data
                .writeEnd();      // event
    }

    private void emitMetrics(CongestionControlMetricsEvent event) {
        jsonGenerator.writeStartObject()
                .write("time", Duration.between(startTime, event.getTime()).toMillis())
                .write("name", "recovery:metrics_updated")
                .writeStartObject("data")
                .write("bytes_in_flight", event.getBytesInFlight())
                .write("congestion_window", event.getCongestionWindow())
                .writeEnd()  // data
                .writeEnd(); // event
    }

    private void emitMetrics(RttMetricsEvent event) {
        jsonGenerator.writeStartObject()
                .write("time", Duration.between(startTime, event.getTime()).toMillis())
                .write("name", "recovery:metrics_updated")
                .writeStartObject("data")
                .write("smoothed_rtt", event.getSmoothedRtt())
                .write("rtt_variance", event.getRttVar())
                .write("latest_rtt", event.getLatestRtt())
                .writeEnd()  // data
                .writeEnd(); // event
    }

    private void emitMetrics(RecoveryMetricsEvent event) {
        jsonGenerator.writeStartObject()
                .write("time", Duration.between(startTime, event.getTime()).toMillis())
                .write("name", "recovery:metrics_updated")
                .writeStartObject("data")
                .write("smoothed_rtt", event.getSmoothedRtt())
                .write("rtt_variance", event.getRttVar())
                .write("latest_rtt", event.getLatestRtt())
                .write("bytes_in_flight", event.getBytesInFlight())
                .write("congestion_window", event.getCongestionWindow())
                .writeEnd()  // data
                .writeEnd(); // event
    }

    private void emitConnectionClosedEvent(ConnectionClosedEvent event) {
        jsonGenerator.writeStartObject()
                .write("time", Duration.between(startTime, event.getTime()).toMillis())
                .write("name", "connectivity:connection_closed")
                .writeStartObject("data")
                .write("trigger", event.getTrigger().qlogFormat());
        if (event.getErrorCode() != null) {
            jsonGenerator.write("connection_code", event.getErrorCode());
        }
        if (event.getErrorReason() != null) {
            jsonGenerator.write("reason", event.getErrorReason());
        }
        jsonGenerator
                .writeEnd()  // data
                .writeEnd(); // event
    }


    private String formatPacketType(QuicPacket packet) {
        if (packet instanceof RetryPacket) {
            return "retry";
        }
        else if (packet instanceof LongHeaderPacket) {
            return packet.getEncryptionLevel().name().toLowerCase();
        }
        else {
            return "1RTT";
        }
    }

    private static String format(byte[] data, String defaultValue) {
        return data != null? Bytes.bytesToHex(data): defaultValue;
    }

    private void writeFooter() {
        jsonGenerator.writeEnd()  // events
                .writeEnd()       // trace
                .writeEnd()       // traces
                .writeEnd();
        jsonGenerator.close();
        System.out.println("QLog: done with " + format(cid, "") + ".qlog");
    }

}
