/*
 * Copyright © 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.sample.push;

import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.log.SysOutLogger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.time.Duration;

import static tech.kwik.core.QuicClientConnection.newBuilder;

/**
 * Sample demo client that implements a simple server push protocol: when a client connects, the server opens a stream
 * and sends push messages.
 */
public class PushClient {

    private int serverPort;
    private QuicClientConnection connection;
    private SysOutLogger log;

    public static void main(String[] args) throws IOException, InterruptedException {
        PushClient client = null;
        try {
            client = new PushClient(Integer.parseInt(args[0]));
        }
        catch (Exception e) {
            System.err.println("Error: expected one argument: server-port-number");
            System.exit(1);
        }

        client.connect();

        Duration runningTime = Duration.ofMinutes(3);
        Thread.sleep(runningTime.toMillis());

        System.out.println("Client has been running for " + runningTime + "; now terminating.");
        client.shutdown();
    }

    public PushClient(int serverPort) {
        this.serverPort = serverPort;
    }

    public void connect() throws IOException {
        log = new SysOutLogger();
        // log.logPackets(true);     // Set various log categories with log.logABC()

        connection = newBuilder()
                .uri(URI.create("push://localhost:" + serverPort))
                .applicationProtocol("push")
                .logger(log)
                .noServerCertificateCheck()
                .build();

        connection.setPeerInitiatedStreamCallback(quicStream -> new Thread(() -> handlePushMessages(quicStream)).start());

        connection.connect();
    }

    private void handlePushMessages(QuicStream quicStream) {
        System.out.println("Server opens stream.");
        BufferedReader inputStream = new BufferedReader(new InputStreamReader(quicStream.getInputStream()));
        try {
            while (true) {
                String line = inputStream.readLine();
                System.out.println("Received " + line);
            }
        }
        catch (Exception e) {
            // Done
        }
    }

    private void shutdown() {
        connection.closeAndWait();
    }
}
