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
package net.luminis.quic.sample.siduck;

import net.luminis.quic.QuicConnection;
import net.luminis.quic.QuicConstants;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.server.ApplicationProtocolConnection;
import net.luminis.quic.server.ApplicationProtocolConnectionFactory;
import net.luminis.quic.server.ServerConnectionConfig;
import net.luminis.quic.server.ServerConnector;

import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;

/**
 * Sample server implementing the Datagram Extension (RFC 9221) show-case protocol named Siduck.
 * See https://datatracker.ietf.org/doc/html/draft-pardue-quic-siduck-00
 */
public class SiduckServer {

    private static void usageAndExit() {
        System.err.println("Usage: cert file, cert key file, port number");
        System.exit(1);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3 || ! Arrays.stream(args).limit(2).allMatch(a -> new File(a).exists())) {
            usageAndExit();
        }

        int port = -1;
        try {
            port = Integer.valueOf(args[2]);
        }
        catch (NumberFormatException noNumber) {
            usageAndExit();
        }

        Logger log = new SysOutLogger();
        log.timeFormat(Logger.TimeFormat.Long);
        log.logWarning(true);
        log.logInfo(true);
        // log.logPackets(true);

        ServerConnectionConfig serverConnectionConfig = ServerConnectionConfig.builder()
                .build();

        ServerConnector serverConnector = ServerConnector.builder()
                .withPort(port)
                .withCertificate(new FileInputStream(args[0]), new FileInputStream(args[1]))
                .withConfiguration(serverConnectionConfig)
                .withLogger(log)
                .build();

        registerProtocolHandler(serverConnector, log);

        serverConnector.start();

        log.info("Started Siduck server on port " + port);
    }

    private static void registerProtocolHandler(ServerConnector serverConnector, Logger log) {
        serverConnector.registerApplicationProtocol("siduck-00", new SiduckConnectionFactory(log));
    }

    /**
     * The factory that creates the application protocol connection.
     */
    static class SiduckConnectionFactory implements ApplicationProtocolConnectionFactory {
        private final Logger log;

        public SiduckConnectionFactory(Logger log) {
            this.log = log;
        }

        @Override
        public boolean enableDatagramExtension() {
            return true;  // Obviously needed for Siduck
        }

        @Override
        public ApplicationProtocolConnection createConnection(String protocol, QuicConnection quicConnection) {
            if (! quicConnection.isDatagramExtensionEnabled()) {
                // If client did not enable the Datagram extension, there is no point in going on, so close connection.
                quicConnection.close(QuicConstants.TransportErrorCode.APPLICATION_ERROR, "Datagram extension not enabled");
                return null;
            }
            return new SiduckConnection(quicConnection, log);
        }

        @Override
        public int maxConcurrentPeerInitiatedUnidirectionalStreams() {
            return 0;  // Because unidirectional streams are not used
        }

        @Override
        public int maxConcurrentPeerInitiatedBidirectionalStreams() {
            return 0;  // Because bidirectional streams are not used
        }
    }

    /**
     * The Siduck protocol connection.
     */
    static class SiduckConnection implements ApplicationProtocolConnection {

        private Logger log;
        private QuicConnection quicConnection;

        public SiduckConnection(QuicConnection quicConnection, Logger log) {
            this.log = log;
            this.quicConnection = quicConnection;
            this.quicConnection.setDatagramHandler(this::handleDatagram);
        }

        private void handleDatagram(byte[] data) {
            log.info("Received datagram with " + data.length + " bytes of data: \"" + new String(data) + "\"");
            quicConnection.sendDatagram("quack-ack".getBytes());
            log.info("Sent datagram with " + "quack-ack".length() + " bytes of data");
        }
    }
}
