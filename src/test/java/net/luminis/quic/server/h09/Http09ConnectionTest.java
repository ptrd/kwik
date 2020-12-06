package net.luminis.quic.server.h09;

import net.luminis.quic.QuicConnection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class Http09ConnectionTest {

    private Http09Connection httpConnection;

    @BeforeEach
    void initObjectUnderTest() {
        httpConnection = new Http09Connection(mock(QuicConnection.class), new File("."));
    }

    @Test
    void extractFileNameFromHttp09Request() throws IOException {
        InputStream input= new ByteArrayInputStream("GET index.html".getBytes());
        String fileName = httpConnection.extractPathFromRequest(input);
        assertThat(fileName).isEqualTo("index.html");
    }

    @Test
    void whenExtractingFileNameFromHttp09RequestInitialSlashIsDiscarded() throws IOException {
        InputStream input= new ByteArrayInputStream("GET /index.html".getBytes());
        String fileName = httpConnection.extractPathFromRequest(input);
        assertThat(fileName).isEqualTo("index.html");
    }

}