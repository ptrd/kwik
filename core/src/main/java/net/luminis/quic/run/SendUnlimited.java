/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.run;

import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.QuicConnection;
import net.luminis.quic.QuicStream;
import net.luminis.quic.log.SysOutLogger;

import java.io.BufferedOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * Sends an unlimited stream to server; used for robustness testing only.
 */
public class SendUnlimited {

    public static void main(String[] args) throws Exception {

        QuicStream stream = null;
        try {
            SysOutLogger log = new SysOutLogger();
            log.logPackets(true);
            log.logInfo(true);

            QuicClientConnection.Builder builder = QuicClientConnection.newBuilder();
            QuicClientConnection connection =
                    builder.version(QuicConnection.QuicVersion.V1)
                            .applicationProtocol("hq-interop")
                            .noServerCertificateCheck()
                            .logger(log)
                            .uri(new URI("https://localhost:4433"))
                            .build();

            connection.connect();

            stream = connection.createStream(true);

            BufferedOutputStream outputStream = new BufferedOutputStream(stream.getOutputStream());
            outputStream.write("GET ".getBytes(StandardCharsets.UTF_8));
            while (true) {
                outputStream.write("abcdefghijklmnopqrstuvwxyz".getBytes(StandardCharsets.UTF_8));
            }
        }
        catch (Exception e) {
            System.out.println("Writing endless request is aborted with an exception " + e);
            System.out.println("Received number of (response) bytes received: " + stream.getInputStream().available());
            // Before exiting, allow quic messages to be sent and received
            Thread.sleep(500);
        }
    }

}
