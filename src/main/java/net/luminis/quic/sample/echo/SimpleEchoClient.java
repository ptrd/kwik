package net.luminis.quic.sample.echo;

import net.luminis.quic.*;
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
 * A simple client that runs a very simple echo protocol on top of QUIC.
 * The echo protocol is a request-response protocol, where the client sends one request on a new stream and the server
 * responds by echoing the data from the request in a response on the same stream. After sending the response, the
 * stream is closed.
 *
 * The main method requires one argument:
 * - port number of the server (server is assumed to run on localhost)
 */
public class SimpleEchoClient {

    private int serverPort;

    public static void main(String[] args) throws IOException {
        SimpleEchoClient client = null;
        try {
            client = new SimpleEchoClient(Integer.parseInt(args[0]));
        }
        catch (Exception e) {
            System.err.println("Error: expected one argument: server-port-number");
            System.exit(1);
        }

        client.echo();
    }

    public SimpleEchoClient(int serverPort) {
        this.serverPort = serverPort;
    }

    public void echo() throws IOException {
        SysOutLogger log = new SysOutLogger();
        // log.logPackets(true);     // Set various log categories with log.logABC()

        QuicClientConnectionImpl connection = QuicClientConnectionImpl.newBuilder()
                .uri(URI.create("echo://localhost:" + serverPort))
                .logger(log)
                .noServerCertificateCheck()
                .build();

        connection.connect(5000, "echo");
        QuicStream quicStream = connection.createStream(true);
        byte[] requestData = "hello mate!".getBytes(StandardCharsets.US_ASCII);
        quicStream.getOutputStream().write(requestData);
        quicStream.getOutputStream().close();

        System.out.print("Response from server: ");
        quicStream.getInputStream().transferTo(System.out);

        connection.close();
    }
}
