package tech.kwik.qlog;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.impl.MockPacket;
import tech.kwik.qlog.event.ConnectionCreatedEvent;
import tech.kwik.qlog.event.PacketLostEvent;
import tech.kwik.qlog.event.PacketSentEvent;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectionQLogTest {

    @Test
    void createShouldGenerateQlogHeader() throws IOException {
        JsonObject qlogResult = createQlogWith(qlog -> {});

        assertThat(qlogResult.getString("qlog_version")).isEqualTo("draft-02");
    }

    @Test
    void processPacketSentEvent() throws IOException {
        var packetSentEvent = new PacketSentEvent(new byte[8], new MockPacket(16, 123, EncryptionLevel.App), Instant.now());
        JsonObject qlogResult = createQlogWith(qlog -> qlog.process(packetSentEvent));

        var sentQlogEvent = getFirstEvent(qlogResult);
        assertThat(sentQlogEvent.getString("name")).isEqualTo("transport:packet_sent");

        var lostQlogEventHeader = sentQlogEvent.getJsonObject("data").getJsonObject("header");
        assertThat(lostQlogEventHeader.getString("packet_type")).isEqualTo("1RTT");
        assertThat(lostQlogEventHeader.getInt("packet_number")).isEqualTo(16);
    }

    @Test
    void processPacketLost() throws IOException {
        var packetLostEvent = new PacketLostEvent(new byte[8], new MockPacket(16, 123, EncryptionLevel.App), Instant.now());
        JsonObject qlogResult = createQlogWith(qlog -> qlog.process(packetLostEvent));

        var lostQlogEvent = getFirstEvent(qlogResult);
        assertThat(lostQlogEvent.getString("name")).isEqualTo("recovery:packet_lost");

        var lostQlogEventHeader = lostQlogEvent.getJsonObject("data").getJsonObject("header");
        assertThat(lostQlogEventHeader.getString("packet_type")).isEqualTo("1RTT");
        assertThat(lostQlogEventHeader.getInt("packet_number")).isEqualTo(16);
    }

    private JsonObject createQlogWith(Consumer<ConnectionQLog> testCase) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(1024);
        ConnectionQLog qLog = new ConnectionQLog(new ConnectionCreatedEvent(new byte[8], Instant.now()), output);
        testCase.accept(qLog);
        qLog.close();

        JsonReader reader = Json.createReader(new ByteArrayInputStream(output.toByteArray()));
        return reader.readObject();
    }

    private JsonObject getFirstEvent(JsonObject qlogResult) {
        JsonObject trace = qlogResult.getJsonArray("traces").getJsonObject(0);
        JsonArray events = trace.getJsonArray("events");
        return events.getJsonObject(0);
    }
}