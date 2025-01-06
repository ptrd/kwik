/*
 * Copyright © 2024, 2025 Peter Doornbosch
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
package tech.kwik.sample.siduck;

import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.log.SysOutLogger;

import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * Sample client implementing the Datagram Extension (RFC 9221) show-case protocol named Siduck.
 * See https://datatracker.ietf.org/doc/html/draft-pardue-quic-siduck-00
 */
public class SiduckClient {

    public static void main(String[] args) throws Exception {

        // If you want to see what happens under the hood, use a logger like this and add to builder with .logger(log)
        SysOutLogger log = new SysOutLogger();
        log.logInfo(true);
        // log.logPackets(true);

        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder();
        QuicClientConnection connection = builder
                .logger(log)
                .noServerCertificateCheck()
                .enableDatagramExtension()
                .uri(new URI(args[0]))
                .applicationProtocol("siduck-00")
                .build();

        connection.connect();

        if (! connection.isDatagramExtensionEnabled()) {
            System.out.println("Error: server did not advertise support for Datagram extension.");
            System.exit(1);
        }

        if (connection.maxDatagramDataSize() < 10) {
            System.out.println("Error: server does not support datagrams of at least 10 bytes.");
            System.exit(1);
        }

        connection.setDatagramHandler(data -> {
            String message = new String(data, StandardCharsets.UTF_8);
            System.out.println("Received datagram: \"" + message + "\"");
        });

        for (int i = 0; i < 3; i++) {
            System.out.println("Sending datagram: \"quack\"");
            connection.sendDatagram("quack".getBytes(StandardCharsets.UTF_8));
            Thread.sleep(1000);
        }

        connection.closeAndWait();
        System.out.println("Connection closed");
    }
}
