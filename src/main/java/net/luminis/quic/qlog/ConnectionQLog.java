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

import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.packet.LongHeaderPacket;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.tls.util.ByteUtils;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Duration;
import java.time.Instant;
import java.util.stream.Collectors;

import static net.luminis.quic.qlog.QLogEvent.Type.PacketReceived;


/**
 * Manages (collects and stores) the qlog file for exactly one quic connection.
 * The log is identified by the original destination connection id.
 */
public class ConnectionQLog {

    private final byte[] cid;
    private Instant startTime;
    private PrintWriter printWriter;

    public ConnectionQLog(byte[] cid) throws IOException {
        this.cid = cid;
        this.startTime = Instant.now();
        printWriter = new PrintWriter(new FileOutputStream(format(cid) + ".qlog"));
        writeHeader();
    }

    public void process(QLogEvent event) {
        if (event.getType() == QLogEvent.Type.PacketSent) {
            writePacketEvent(event);
        }
        else if (event.getType() == PacketReceived) {
            writePacketEvent(event);
        }
        else if (event.getType() == QLogEvent.Type.EndConnection) {
            close();
        }
    }

    public void close() {
        writeFooter();
    }

    private void writeHeader() {
        printWriter.println("{\"qlog_version\": \"draft-01\", "
                + "\"traces\": [{\"vantage_point\": { \"name\": \"kwik\", \"type\": \"server\" }, \"configuration\": {\"time_units\": \"ms\"}, \"common_fields\": {\"ODCID\": \"" + ByteUtils.bytesToHex(cid)
                + "\", \"reference_time\": \"" + startTime.toEpochMilli() + "\"}, \"event_fields\": [\"relative_time\", \"category\", \"event_type\", \"data\"], \"events\": [");
    }

    private void writePacketEvent(QLogEvent event) {
        long relativeTime = Duration.between(startTime, event.getTime()).toMillis();
        QuicPacket packet = event.getPacket();
            if (!first) {
                printWriter.println(",");
            }
            else {
                first = false;
            }

            printWriter.println("[\"" + relativeTime + "\", \"transport\", \""
                    + (event.getType() == PacketReceived? "packet_received": "packet_sent") + "\", "
                    + "{\"packet_type\": \"" + formatPacketType(packet)  + "\", "
                    + "\"header\": {\"packet_number\": \"" + packet.getPacketNumber() + "\", \"packet_size\": " + packet.getSize()
                    + ", \"dcid\": \"" + format(packet.getDestinationConnectionId()) + "\""
                    + (packet instanceof LongHeaderPacket? ", \"scid\": \"" + format(((LongHeaderPacket) packet).getSourceConnectionId()) + "\"": "")
                    + "}, "
                    + "\"frames\": [");

            printWriter.println(packet.getFrames().stream().map(f -> formatFrame(f)).collect(Collectors.joining(",")));
            printWriter.println("]}]");
    }

    private String formatPacketType(QuicPacket packet) {
        if (packet instanceof LongHeaderPacket) {
            return packet.getEncryptionLevel().name().toLowerCase();
        }
        else {
            return "1RTT";
        }
    }
    private String formatFrame(QuicFrame f) {
        return "{\"frame_type\": \"" +
                f.getClass().getSimpleName().replace("Frame", "").toLowerCase()
                + "\" }";
    }

    private String format(byte[] data) {
        return ByteUtils.bytesToHex(data);
    }

    boolean first = true;

    private void writeFooter() {
        printWriter.println("]}]}");
        printWriter.flush();
        printWriter.close();
        System.out.println("QLog: done with " + format(cid) + ".qlog");
    }

}
