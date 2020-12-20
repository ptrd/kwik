package net.luminis.quic.qlog;

import net.luminis.quic.frame.AckFrame;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.json.Json;
import javax.json.stream.JsonGenerator;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

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
        AckFrame ackFrame = new AckFrame(List.of(1l, 2l, 3l, 6l, 7l));
        System.out.println("String:" + ackFrame);
        frameFormatter.process(ackFrame, null, null);
        jsonGenerator.flush();
        System.out.println("Json:" + output.toString());
        assertThat(output.toString()).contains("\"acked_ranges\":[[1,3],[6,7]");
    }

    @Test
    void formatAckFrameWithSingleElementRanges() {
        AckFrame ackFrame = new AckFrame(List.of(1l, 2l, 3l, 6l, 8l, 9l));
        System.out.println("String:" + ackFrame);
        frameFormatter.process(ackFrame, null, null);
        jsonGenerator.flush();
        System.out.println("Json:" + output.toString());
        assertThat(output.toString()).contains("\"acked_ranges\":[[1,3],[6,6],[8,9]]");
    }

    @Test
    void formatAckFrameWithSingleElement() {
        AckFrame ackFrame = new AckFrame(List.of(3l));
        System.out.println("String:" + ackFrame);
        frameFormatter.process(ackFrame, null, null);
        jsonGenerator.flush();
        System.out.println("Json:" + output.toString());
        assertThat(output.toString()).contains("\"acked_ranges\":[[3,3]]");
    }
}