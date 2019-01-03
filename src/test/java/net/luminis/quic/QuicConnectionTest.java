package net.luminis.quic;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class QuicConnectionTest {

    @Test
    void createStream() throws IOException {
        QuicConnection connection = new QuicConnection("localhost", 443, Version.IETF_draft_15, Mockito.mock(Logger.class));

        QuicStream stream = connection.createStream(true);
        int firstStreamId = stream.getStreamId();
        int streamIdLowBits = firstStreamId & 0x03;

        assertThat(streamIdLowBits).isEqualTo(0x00);

        QuicStream stream2 = connection.createStream(true);
        assertThat(stream2.getStreamId()).isEqualTo(firstStreamId + 4);
    }
}