/*
 * Copyright © 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.sample.echo;

import net.luminis.quic.QuicClientConnection;
import net.luminis.quic.QuicConnection;
import net.luminis.quic.QuicSessionTicket;
import net.luminis.quic.QuicStream;
import net.luminis.quic.core.QuicSessionTicketImpl;
import net.luminis.quic.log.SysOutLogger;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Collections;
import java.util.List;

/**
 * A simple client that runs a very simple echo protocol on top of QUIC. This client will use 0-RTT when possible.
 *
 * The echo protocol is a request-response protocol, where the client sends one request on a new stream and the server
 * responds by echoing the data from the request in a response on the same stream. After sending the response, the
 * stream is closed.
 *
 * If a session ticket can be found, this client tries to setup the QUIC connection with the session ticket and
 * send its request data via 0-RTT. A session ticket is saved to file (named echoclientsessionticket.bin), so just
 * run the client a single time to obtain a session ticket.
 *
 * The class' main method requires one argument:
 * - port number of the server (which is assumed to run on localhost)
 */

public class EchoClientUsing0RTT {

    public static final String SESSIONTICKET_FILE = "echoclientsessionticket.bin";

    private int serverPort;

    public static void main(String[] args) throws IOException {
        try {
            EchoClientUsing0RTT client = new EchoClientUsing0RTT(Integer.parseInt(args[0]));
            client.run();
        }
        catch (NumberFormatException e) {
            System.err.println("Error: expected one argument: server-port-number");
            System.exit(1);
        }

    }

    public EchoClientUsing0RTT(int serverPort) {
        this.serverPort = serverPort;
    }

    public void run() throws IOException {
        byte[] requestData = "hello mate!".getBytes(StandardCharsets.US_ASCII);

        SysOutLogger log = new SysOutLogger();
        log.logPackets(true);    // When 0-RTT is used, log will show a 0-RTT packet like "Packet Z|0|Z|52|1  StreamFrame[0(CIB),0,11,fin]"

        // Create connection builder (do not yet create connection!)
        QuicClientConnection.Builder connectionBuilder = QuicClientConnection.newBuilder()
                .uri(URI.create("echo://localhost:" + serverPort))
                .logger(log)
                .version(QuicConnection.QuicVersion.V1)
                .applicationProtocol("echo")
                .noServerCertificateCheck();

        // Try to load session ticket and if it can be loaded, create early data.
        List<QuicClientConnection.StreamEarlyData> earlyData = Collections.emptyList();
        try {
            byte[] ticketData = Files.readAllBytes(Path.of(SESSIONTICKET_FILE));
            connectionBuilder.sessionTicket(QuicSessionTicketImpl.deserialize(ticketData));   // This is why the connection should not yet have been created!
            earlyData = List.of(new QuicClientConnection.StreamEarlyData(requestData, true));
        }
        catch (IOException e) {
            System.err.println("Cannot read/load session ticket; will not be using 0-RTT!");
        }

        // Create connection with 0-RTT data
        QuicClientConnection connection = connectionBuilder.build();
        List<QuicStream> earlyStreams = connection.connect(earlyData);
        // Connect does create and return streams if earlyData parameter is empty (which is the case here when no session ticket was loaded, see above)
        QuicStream quicStream = earlyStreams.stream()
                .findAny()
                .orElseGet(() -> {
                    try {
                        QuicStream s = connection.createStream(true);
                        s.getOutputStream().write(requestData);
                        s.getOutputStream().close();
                        return s;
                    }
                    catch (IOException ioe) {
                        throw new UncheckedIOException(ioe);
                    }
                });

        System.out.print("Response from server: ");
        quicStream.getInputStream().transferTo(System.out);

        // Save one session ticket for a next invocation.
        List<QuicSessionTicket> newSessionTickets = connection.getNewSessionTickets();
        connection.closeAndWait();

        // Note that session tickets are server specific, so if the client can connect to an arbitrary server, the
        // ticket should be saved in a way that the origin server can be identified.
        newSessionTickets.forEach(ticket ->
        {
            try {
                Files.write(Path.of(SESSIONTICKET_FILE), ticket.serialize(), StandardOpenOption.CREATE);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }
}
