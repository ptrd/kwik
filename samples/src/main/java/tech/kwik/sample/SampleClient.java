/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.sample;

import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.log.SysOutLogger;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;


/**
 * Sample with the smallest / simplest Java program to setup and use a QUIC connection,
 * assuming the server implements HTTP 0.9 protocol
 * (which is a simplified version of HTTP 1, see https://medium.com/platform-engineer/evolution-of-http-69cfe6531ba0).
 *
 * Retrieves "/" resource and safes content to file.
 * Usage: expects one argument: the address of the server, e.g. http://quicserver:4433
 */
public class SampleClient {

    public static void main(String[] args) throws Exception {

        // If you want to see what happens under the hood, use a logger like this and add to builder with .logger(log)
        SysOutLogger log = new SysOutLogger();
        log.logPackets(true);
        log.logInfo(true);


        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder();
        QuicClientConnection connection = builder
                .uri(new URI(args[0]))
                // The early QUIC implementors choose "hq-interop" as the ALPN identifier for running HTTP 0.9 on top of QUIC,
                // see https://github.com/quicwg/base-drafts/wiki/21st-Implementation-Draft
                .applicationProtocol("hq-interop")
                .build();

        connection.connect();

        QuicStream stream = connection.createStream(true);

        BufferedOutputStream outputStream = new BufferedOutputStream(stream.getOutputStream());
        // HTTP 0.9 really is very simple: a GET request without any headers.
        outputStream.write("GET / \r\n".getBytes(StandardCharsets.UTF_8));
        outputStream.flush();

        long transferred = stream.getInputStream().transferTo(new FileOutputStream("kwik_client_output"));

        connection.close();

        System.out.println("Received " + transferred + " bytes.");
    }
}
