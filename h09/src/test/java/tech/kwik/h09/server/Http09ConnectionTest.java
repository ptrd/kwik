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
package tech.kwik.h09.server;

import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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

    @Test
    void whenRequestingExistingFileContentIsReturned() throws Exception {
        Path wwwDir = Files.createTempDirectory("kwikh09");
        Files.write(Paths.get(wwwDir.toString(), "test.txt"), "This is a test (obviously)\n".getBytes());

        Http09Connection http09Connection = new Http09Connection(mock(QuicConnection.class), wwwDir.toFile());

        QuicStream quicStream = mock(QuicStream.class);
        when(quicStream.getInputStream()).thenReturn(new ByteArrayInputStream("GET test.txt".getBytes()));
        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream(1024);
        when(quicStream.getOutputStream()).thenReturn(arrayOutputStream);
        http09Connection.handleRequest(quicStream);

        assertThat(arrayOutputStream.toString()).startsWith("This is a test");
    }

    @Test
    void whenRequestingNonExistingFile404Returned() throws Exception {
        Path wwwDir = Files.createTempDirectory("kwikh09");

        Http09Connection http09Connection = new Http09Connection(mock(QuicConnection.class), wwwDir.toFile());

        QuicStream quicStream = mock(QuicStream.class);
        when(quicStream.getInputStream()).thenReturn(new ByteArrayInputStream("GET doesnotexist.txt".getBytes()));
        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream(1024);
        when(quicStream.getOutputStream()).thenReturn(arrayOutputStream);
        http09Connection.handleRequest(quicStream);

        assertThat(arrayOutputStream.toString()).startsWith("404");
    }

    @Test
    void pathTraversalShouldBePrevented() throws Exception {
        Path rootDir = Files.createTempDirectory("kwikh09");
        Files.write(Paths.get(rootDir.toString(), "secrets"), "This is a secret\n".getBytes());

        File wwwDir = new File(rootDir.toFile(), "www");
        wwwDir.mkdirs();
        Files.write(Paths.get(wwwDir.toString(), "test.txt"), "This is a test (obviously)\n".getBytes());

        Http09Connection http09Connection = new Http09Connection(mock(QuicConnection.class), wwwDir);

        QuicStream quicStream = mock(QuicStream.class);
        when(quicStream.getInputStream()).thenReturn(new ByteArrayInputStream("GET ../secrets".getBytes()));
        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream(1024);
        when(quicStream.getOutputStream()).thenReturn(arrayOutputStream);
        http09Connection.handleRequest(quicStream);

        assertThat(arrayOutputStream.toString()).startsWith("404");
    }

}