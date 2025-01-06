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

import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.SysOutLogger;
import tech.kwik.core.server.ApplicationProtocolConnection;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;


/**
 * Sample demo server that implements a simple push protocol: when a client connects, the server opens a stream and sends
 * push messages.
 *
 *  The server's main method requires three arguments:
 * - certificate file (can be self-signed)
 * - key file with the private key of the certificate
 * - port number
 *
 * Set environment variable QLOGDIR to let the server create qlog files.
 */
public class PushServer {

    private static void usageAndExit() {
        System.err.println("Usage: cert file, cert key file, port number");
        System.exit(1);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3 || !Arrays.stream(args).limit(2).allMatch(a -> new File(a).exists())) {
            usageAndExit();
        }

        int port = -1;
        try {
            port = Integer.valueOf(args[2]);
        } catch (NumberFormatException noNumber) {
            usageAndExit();
        }

        Logger log = new SysOutLogger();
        log.timeFormat(Logger.TimeFormat.Long);
        log.logWarning(true);
        log.logInfo(true);

        ServerConnectionConfig serverConnectionConfig = ServerConnectionConfig.builder()
                // No connection configuration necessary, as client will not initiate any stream, nor send data.
                .build();

        ServerConnector serverConnector = ServerConnector.builder()
                .withPort(port)
                .withCertificate(new FileInputStream(args[0]), new FileInputStream(args[1]))
                .withConfiguration(serverConnectionConfig)
                .withLogger(log)
                .build();

        registerProtocolHandler(serverConnector, log);

        serverConnector.start();

        log.info("Started (msg) push server on port " + port);
    }

    private static void registerProtocolHandler(ServerConnector serverConnector, Logger log) {
        serverConnector.registerApplicationProtocol("push", new PushProtocolConnectionFactory(log));
    }

    /**
     * The factory that creates the (push) application protocol connection.
     */
    static class PushProtocolConnectionFactory implements ApplicationProtocolConnectionFactory {

        private Logger log;

        public PushProtocolConnectionFactory(Logger log) {
            this.log = log;
        }

        @Override
        public ApplicationProtocolConnection createConnection(String protocol, QuicConnection quicConnection) {
            return new PushProtocolConnection(quicConnection, log);
        }
    }

    /**
     * The connection that implements the (push) application protocol.
     */
    static class PushProtocolConnection implements ApplicationProtocolConnection {

        private Logger log;

        public PushProtocolConnection(QuicConnection quicConnection, Logger log) {
            this.log = log;
            System.out.println("New \"push protocol\" connection; will create (server initiated) stream to push messages to client.");
            try {
            QuicStream quicStream = quicConnection.createStream(false);
            new Thread(() -> generatePushMessages(quicStream), "pusher").start();
        }
            catch (IOException e) {
                // QuicConnection closed before stream could be created; ignore.
            }
        }

        private void generatePushMessages(QuicStream quicStream) {
            OutputStream outputStream = quicStream.getOutputStream();
            try {
                while (true) {
                    String currentDateTime = Instant.now().toString();
                    System.out.println("Pushing message " + currentDateTime);
                    outputStream.write(currentDateTime.getBytes(StandardCharsets.US_ASCII));
                    outputStream.write("\n".getBytes(StandardCharsets.US_ASCII));
                    Thread.sleep(1000);
                }
            }
            catch (Exception e) {
                System.out.println("Pushing messages terminated with exception " + e);
            }
        }
    }
}
