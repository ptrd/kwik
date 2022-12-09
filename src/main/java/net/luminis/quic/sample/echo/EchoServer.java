package net.luminis.quic.sample.echo;

import net.luminis.quic.QuicConnection;
import net.luminis.quic.QuicStream;
import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.server.ApplicationProtocolConnection;
import net.luminis.quic.server.ApplicationProtocolConnectionFactory;
import net.luminis.quic.server.ServerConnector;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;


/**
 * A simple server that runs a very simple echo protocol on top of QUIC.
 * The echo protocol is a request-response protocol, where the client sends one request on a new stream and the server
 * responds by echoing the data from the request in a response on the same stream. After sending the response, the
 * stream is closed.
 *
 * The server's main method requires three arguments:
 * - certificate file (can be self-signed)
 * - key file with the private key of the certificate
 * - port number
 */
public class EchoServer {

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

        ServerConnector serverConnector = new ServerConnector(port, new FileInputStream(args[0]), new FileInputStream(args[1]), List.of(Version.QUIC_version_1), false, log);

        registerProtocolHandler(serverConnector, log);

        serverConnector.start();

        log.info("Started echo server on port " + port);
    }

    private static void registerProtocolHandler(ServerConnector serverConnector, Logger log) {
           serverConnector.registerApplicationProtocol("echo", new ApplicationProtocolConnectionFactory() {

               @Override
               public ApplicationProtocolConnection createConnection(String protocol, QuicConnection quicConnection) {
                   return new EchoProtocolConnection(quicConnection, log);
               }
           });
    }

    static class EchoProtocolConnection extends ApplicationProtocolConnection implements Consumer<QuicStream> {

        private Logger log;

        public EchoProtocolConnection(QuicConnection quicConnection, Logger log) {
            this.log = log;
            quicConnection.setPeerInitiatedStreamCallback(this);
        }

        @Override
        public void accept(QuicStream quicStream) {
            new Thread(() -> handleEchoRequest(quicStream)).start();
        }

        private void handleEchoRequest(QuicStream quicStream) {
            try {
                // Note that this implementation is not safe to use in the wild, as attackers can crash the server by sending arbitrary long requests.
                byte[] bytesRead = quicStream.getInputStream().readAllBytes();
                System.out.println("Read echo request with " + bytesRead.length + " bytes of data.");
                quicStream.getOutputStream().write(bytesRead);
                quicStream.getOutputStream().close();
            } catch (IOException e) {
                log.error("Reading quic stream failed", e);
            }
        }
    }
}
