/*
 * Copyright © 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.qlog;

import jakarta.json.Json;
import jakarta.json.stream.JsonGenerator;
import net.luminis.quic.ack.Range;
import net.luminis.quic.frame.AckFrame;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class FrameFormatterTest {

    private ByteArrayOutputStream output;
    private FrameFormatter frameFormatter;
    private JsonGenerator jsonGenerator;

    @BeforeEach
    void initObjectUnderTest() {
        output = new ByteArrayOutputStream(1024);
        jsonGenerator = Json.createGenerator(output);
        frameFormatter = new FrameFormatter(jsonGenerator);
    }

    @Test
    void formatAckFrameWithRanges() {
        AckFrame ackFrame = new AckFrame(List.of(new Range(6l, 7l), new Range(1l, 3l)));
        frameFormatter.process(ackFrame, null, null);
        jsonGenerator.flush();
        assertThat(output.toString()).contains("\"acked_ranges\":[[1,3],[6,7]");
    }

    @Test
    void formatAckFrameWithSingleElementRanges() {
        AckFrame ackFrame = new AckFrame(List.of(new Range(8l, 9l), new Range(6l), new Range(1l, 3l)));
        frameFormatter.process(ackFrame, null, null);
        jsonGenerator.flush();
        assertThat(output.toString()).contains("\"acked_ranges\":[[1,3],[6,6],[8,9]]");
    }

    @Test
    void formatAckFrameWithSingleElement() {
        AckFrame ackFrame = new AckFrame(3l);
        frameFormatter.process(ackFrame, null, null);
        jsonGenerator.flush();
        assertThat(output.toString()).contains("\"acked_ranges\":[[3,3]]");
    }
}