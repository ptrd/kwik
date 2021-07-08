/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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

import net.luminis.quic.*;
import net.luminis.quic.client.h09.Http09Client;
import net.luminis.quic.log.FileLogger;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.stream.QuicStream;
import net.luminis.tls.NewSessionTicket;
import net.luminis.tls.TlsConstants;
import org.apache.commons.cli.*;

import java.io.*;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.rmi.RemoteException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Command line interface for Kwik
 */
public class KwikCli {

    private static Options cmdLineOptions;
    private static String DEFAULT_LOG_ARGS = "wip";


    public static void main(String[] rawArgs) throws ParseException {
        cmdLineOptions = new Options();
        cmdLineOptions.addOption("l", "log", true, "logging options: [pdrcsiRSD]: " +
                "(p)ackets received/sent, (d)ecrypted bytes, (r)ecovery, (c)ongestion control, (s)tats, (i)nfo, (w)arning, (R)aw bytes, (S)ecrets, (D)ebug; "
                + " default is \"" + DEFAULT_LOG_ARGS + "\", use (n)one to disable");
        cmdLineOptions.addOption("h", "help", false, "show help");
        cmdLineOptions.addOption("29", "use Quic version IETF_draft_29");
        cmdLineOptions.addOption("30", "use Quic version IETF_draft_30");
        cmdLineOptions.addOption("31", "use Quic version IETF_draft_31");
        cmdLineOptions.addOption("32", "use Quic version IETF_draft_32");
        cmdLineOptions.addOption("v1", "use Quic version 1");
        cmdLineOptions.addOption(null, "reservedVersion", false, "use reserved version to trigger version negotiation");
        cmdLineOptions.addOption("A", "alpn", true, "set alpn (default is hq-xx)");
        cmdLineOptions.addOption("R", "resumption key", true, "session ticket file");
        cmdLineOptions.addOption("c", "connectionTimeout", true, "connection timeout in seconds");
        cmdLineOptions.addOption("i", "interactive", false, "start interactive shell");
        cmdLineOptions.addOption("k", "keepAlive", true, "connection keep alive time in seconds");
        cmdLineOptions.addOption("L", "logFile", true, "file to write log message to");
        cmdLineOptions.addOption("O", "output", true, "write server response to file");
        cmdLineOptions.addOption("H", "http09", true, "send HTTP 0.9 request, arg is path, e.g. '/index.html'");
        cmdLineOptions.addOption("S", "storeTickets", true, "basename of file to store new session tickets");
        cmdLineOptions.addOption("T", "relativeTime", false, "log with time (in seconds) since first packet");
        cmdLineOptions.addOption("Z", "use0RTT", false, "use 0-RTT if possible (requires -H)");
        cmdLineOptions.addOption(null, "secrets", true, "write secrets to file (Wireshark format)");
        cmdLineOptions.addOption("v", "version", false, "show Kwik version");
        cmdLineOptions.addOption(null, "initialRtt", true, "custom initial RTT value (default is 500)");
        cmdLineOptions.addOption(null, "chacha20", false, "use ChaCha20 as only cipher suite");
        cmdLineOptions.addOption(null, "noCertificateCheck", false, "do not check server certificate");
        cmdLineOptions.addOption(null, "saveServerCertificates", true, "store server certificates in given file");
        cmdLineOptions.addOption(null, "quantumReadinessTest", true, "add number of random bytes to client hello");
        cmdLineOptions.addOption(null, "clientCertificate", true, "certificate (file) for client authentication");
        cmdLineOptions.addOption(null, "clientKey", true, "private key (file) for client certificate");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = parser.parse(cmdLineOptions, rawArgs);
        }
        catch (ParseException argError) {
            System.out.println("Invalid argument: " + argError.getMessage());
            usage();
            System.exit(1);
        }

        if (cmd.hasOption("v")) {
            System.out.println("Kwik build nr: " + KwikVersion.getVersion());
            System.exit(0);
        }

        List<String> args = cmd.getArgList();
        if (args.size() == 0) {
            usage();
            return;
        }

        QuicClientConnectionImpl.Builder builder = QuicClientConnectionImpl.newBuilder();
        String httpRequestPath = null;
        if (args.size() == 1) {
            String arg = args.get(0);
            try {
                if (arg.startsWith("http://") || arg.startsWith("https://")) {
                    try {
                        URL url = new URL(arg);
                        builder.uri(url.toURI());
                        if (!url.getPath().isEmpty()) {
                            httpRequestPath = url.getPath();
                        }
                    } catch (MalformedURLException e) {
                        System.out.println("Cannot parse URL '" + arg + "'");
                        return;
                    }
                } else if (arg.contains(":")) {
                    builder.uri(new URI("//" + arg));
                } else {
                    if (arg.matches("\\d+")) {
                        System.out.println("Error: invalid hostname (did you forget to specify an option argument?).");
                        usage();
                        return;
                    }
                    builder.uri(new URI("//" + arg + ":" + 443));
                }
            } catch (URISyntaxException invalidUri) {
                System.out.println("Cannot parse URI '" + arg + "'");
                return;
            }
        }
        else if (args.size() == 2) {
            try {
                builder.uri(new URI("//" + args.get(0) + ":" + args.get(1)));
            } catch (URISyntaxException invalidUri) {
                System.out.println("Cannot parse URI '" + args.stream().collect(Collectors.joining(":")) + "'");
                return;
            }
        }
        else if (args.size() > 2) {
            usage();
            return;
        }

        if (cmd.hasOption("chacha20")) {
            builder.cipherSuite(TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        }

        if (cmd.hasOption("noCertificateCheck")) {
            builder.noServerCertificateCheck();
        }

        String serverCertificatesFile = null;
        if (cmd.hasOption("saveServerCertificates")) {
            serverCertificatesFile = cmd.getOptionValue("saveServerCertificates");
        }

        Logger logger = null;
        if (cmd.hasOption("L")) {
            String logFilename = cmd.getOptionValue("L");
            try {
                logger = new FileLogger(new File(logFilename));
            } catch (IOException fileError) {
                System.err.println("Error: cannot open log file '" + logFilename + "'");
            }
        }
        if (logger == null) {
            logger = new SysOutLogger();
        }
        builder.logger(logger);

        String logArg = DEFAULT_LOG_ARGS;
        if (cmd.hasOption('l')) {
            logArg = cmd.getOptionValue('l', logArg);
        }

        if (!logArg.contains("n")) {
            if (logArg.contains("R")) {
                logger.logRaw(true);
            }
            if (logArg.contains("r")) {
                logger.logRecovery(true);
            }
            if (logArg.contains("c")) {
                logger.logCongestionControl(true);
            }
            if (logArg.contains("d")) {
                logger.logDecrypted(true);
            }
            if (logArg.contains("S")) {
                logger.logSecrets(true);
            }
            if (logArg.contains("p")) {
                logger.logPackets(true);
            }
            if (logArg.contains("i")) {
                logger.logInfo(true);
            }
            if (logArg.contains("w")) {
                logger.logWarning(true);
            }
            if (logArg.contains("s")) {
                logger.logStats(true);
            }
            if (logArg.contains("D")) {
                logger.logDebug(true);
            }
        }

        Version quicVersion = Version.getDefault();

        if (cmd.hasOption("v1")) {
            quicVersion = Version.QUIC_version_1;
        }
        else if (cmd.hasOption("32")) {
            quicVersion = Version.IETF_draft_32;
        }
        else if (cmd.hasOption("31")) {
            quicVersion = Version.IETF_draft_31;
        }
        else if (cmd.hasOption("30")) {
            quicVersion = Version.IETF_draft_30;
        }
        else if (cmd.hasOption("29")) {
            quicVersion = Version.IETF_draft_29;
        }

        if (cmd.hasOption("reservedVersion")) {
            quicVersion = Version.reserved_1;
        }
        builder.version(quicVersion);

        String alpn = null;
        if (cmd.hasOption("A")) {
            alpn = cmd.getOptionValue("A", null);
            if (alpn == null) {
                usage();
                System.exit(1);
            }
        }

        int connectionTimeout = 5;
        if (cmd.hasOption("c")) {
            try {
                connectionTimeout = Integer.parseInt(cmd.getOptionValue("c", "5"));
            } catch (NumberFormatException e) {
                usage();
                System.exit(1);
            }
        }

        int keepAliveTime = 0;
        if (cmd.hasOption("k")) {
            try {
                keepAliveTime = Integer.parseInt(cmd.getOptionValue("k"));
            }
            catch (NumberFormatException e) {
                usage();
                System.exit(1);
            }
        }

        boolean useZeroRtt = false;
        if (cmd.hasOption("Z")) {
            useZeroRtt = true;
        }
        if (cmd.hasOption("H")) {
            httpRequestPath = cmd.getOptionValue("H");
            if (httpRequestPath == null) {
                usage();
                System.exit(1);
            }
            else {
                if (! httpRequestPath.startsWith("/")) {
                    httpRequestPath = "/" + httpRequestPath;

                }
            }
        }
        if (useZeroRtt && httpRequestPath == null) {
            usage();
            System.exit(1);
        }

        String outputFile = null;
        if (cmd.hasOption("O")) {
            outputFile = cmd.getOptionValue("O");
            if (outputFile == null) {
                usage();
                System.exit(1);
            }
            if (Files.exists(Paths.get(outputFile)) && !Files.isWritable(Paths.get(outputFile))) {
                System.err.println("Output file '" + outputFile + "' is not writable.");
                System.exit(1);
            }
        }

        if (cmd.hasOption("secrets")) {
            String secretsFile = cmd.getOptionValue("secrets");
            if (secretsFile == null) {
                usage();
                System.exit(1);
            }
            if (Files.exists(Paths.get(secretsFile)) && !Files.isWritable(Paths.get(secretsFile))) {
                System.err.println("Secrets file '" + secretsFile + "' is not writable.");
                System.exit(1);
            }
            builder.secrets(Paths.get(secretsFile));
        }

        String newSessionTicketsFilename = null;
        if (cmd.hasOption("S")) {
            newSessionTicketsFilename = cmd.getOptionValue("S");
            if (newSessionTicketsFilename == null) {
                usage();
                System.exit(1);
            }
        }

        QuicSessionTicket sessionTicket = null;
        if (cmd.hasOption("R")) {
            String sessionTicketFile = null;
            sessionTicketFile = cmd.getOptionValue("R");
            if (sessionTicketFile == null) {
                usage();
                System.exit(1);
            }
            if (!Files.isReadable(Paths.get(sessionTicketFile))) {
                System.err.println("Session ticket file '" + sessionTicketFile + "' is not readable.");
                System.exit(1);
            }
            byte[] ticketData = new byte[0];
            try {
                ticketData = Files.readAllBytes(Paths.get(sessionTicketFile));
                sessionTicket = QuicSessionTicket.deserialize(ticketData);
                builder.sessionTicket(sessionTicket);
            } catch (IOException e) {
                System.err.println("Error while reading session ticket file.");
            }
        }
        if (useZeroRtt && sessionTicket == null) {
            System.err.println("Using 0-RTT requires a session ticket");
            System.exit(1);
        }

        if (cmd.hasOption("clientCertificate") && cmd.hasOption("clientKey")) {
            try {
                builder.clientCertificate(readCertificate(cmd.getOptionValue("clientCertificate")));
                builder.clientCertificateKey(readKey(cmd.getOptionValue("clientKey")));
            }
            catch (Exception e) {
                System.err.println("Loading client certificate/key failed: " + e);
                System.exit(1);
            }
        }
        else if (cmd.hasOption("clientCertificate") || cmd.hasOption("clientKey")) {
            System.err.println("Options --clientCertificate and --clientKey should always be used together");
            System.exit(1);
        }

        if (cmd.hasOption("quantumReadinessTest")) {
            try {
                builder.quantumReadinessTest(Integer.parseInt(cmd.getOptionValue("quantumReadinessTest")));
            } catch (NumberFormatException e) {
                usage();
                System.exit(1);
            }
        }

        if (cmd.hasOption("T")) {
            logger.useRelativeTime(true);
        }

        boolean interactiveMode = cmd.hasOption("i");
        if (cmd.hasOption("initialRtt")) {
            try {
                builder.initialRtt(Integer.parseInt(cmd.getOptionValue("initialRtt")));
            } catch (NumberFormatException e) {
                usage();
                System.exit(1);
            }
        }

        try {
            if (interactiveMode) {
                new InteractiveShell(builder, alpn).start();
            }
            else {
                QuicStream httpStream = null;
                QuicClientConnection quicConnection = builder.build();
                if (useZeroRtt && httpRequestPath != null) {
                    String http09Request = "GET " + httpRequestPath + "\r\n";
                    QuicClientConnection.StreamEarlyData earlyData = new QuicClientConnection.StreamEarlyData(http09Request.getBytes(), true);
                    httpStream = quicConnection.connect(connectionTimeout * 1000, "hq-27", null, List.of(earlyData)).get(0);
                }
                else {
                    if (alpn == null) {
                        quicConnection.connect(connectionTimeout * 1000);
                    } else {
                        quicConnection.connect(connectionTimeout * 1000, alpn, null, null);
                    }
                }

                if (keepAliveTime > 0) {
                    quicConnection.keepAlive(keepAliveTime);
                }

                if (serverCertificatesFile != null) {
                    storeServerCertificates(quicConnection, serverCertificatesFile);
                }

                if (httpRequestPath != null) {
                    try {
                        HttpClient httpClient = new Http09Client(quicConnection);
                        InetSocketAddress serverAddress = quicConnection.getServerAddress();
                        HttpRequest request = HttpRequest.newBuilder()
                                .uri(new URI("https", null, serverAddress.getHostName(), serverAddress.getPort(), httpRequestPath, null, null))
                                .build();

                        if (outputFile != null) {
                            httpClient.send(request, HttpResponse.BodyHandlers.ofFile(Paths.get(outputFile)));
                        }
                        else {
                            HttpResponse<String> httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                            // Wait a little to let logger catch up, so output is printed nicely after all the handshake logging....
                            try {
                                Thread.sleep(500);
                            }
                            catch (InterruptedException e) {}

                            System.out.println("Server returns: \n" + httpResponse.body());
                        }
                    }
                    catch (InterruptedException interruptedException) {
                        System.out.println("HTTP request is interrupted");
                    }
                    catch (URISyntaxException e) {
                        // Impossible
                        throw new RuntimeException();
                    }
                }
                else {
                    if (keepAliveTime > 0) {
                        try {
                            Thread.sleep((keepAliveTime + 30) * 1000);
                        } catch (InterruptedException e) {
                        }
                    }
                }

                if (newSessionTicketsFilename != null) {
                    storeNewSessionTickets(quicConnection, newSessionTicketsFilename);
                }
                quicConnection.close();

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                }
            }

            System.out.println("Terminating Kwik");
        }
        catch (IOException e) {
            System.out.println("Got IO error: " + e);
        }
        catch (VersionNegotiationFailure e) {
            System.out.println("Client and server could not agree on a compatible QUIC version.");
        }

        if (!interactiveMode && httpRequestPath == null && keepAliveTime == 0) {
            System.out.println("This was quick, huh? Next time, consider using --http09 or --keepAlive argument.");
        }
    }

    private static PrivateKey readKey(String clientKey) throws IOException, InvalidKeySpecException {
        String key = new String(Files.readAllBytes(Paths.get(clientKey)), Charset.defaultCharset());

        if (key.contains("BEGIN PRIVATE KEY")) {
            return loadRSAKey(key);
        }
        else if (key.contains("BEGIN EC PRIVATE KEY")) {
            throw new IllegalArgumentException("EC private key must be in DER format");
        }
        else {
            // Assume DER format
            return loadECKey(Files.readAllBytes(Paths.get(clientKey)));
        }
    }

    private static PrivateKey loadRSAKey(String key) throws InvalidKeySpecException {
        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.getMimeDecoder().decode(privateKeyPEM);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing key algorithm RSA");
        }
    }

    private static PrivateKey loadECKey(byte[] pkcs8key) throws InvalidKeySpecException {
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8key);
            KeyFactory factory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = factory.generatePrivate(spec);
            return privateKey;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing ECDSA support");
        }
    }

    private static X509Certificate readCertificate(String certificateFile) throws IOException, CertificateException {
        String fileContent = new String(Files.readAllBytes(Paths.get(certificateFile)), Charset.defaultCharset());

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        if (fileContent.startsWith("-----BEGIN CERTIFICATE-----")) {
                String encodedCertificate = fileContent
                        .replace("-----BEGIN CERTIFICATE-----", "")
                        .replaceAll(System.lineSeparator(), "")
                        .replace("-----END CERTIFICATE-----", "");
            Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate)));
            return (X509Certificate) certificate;
        }
        else {
            throw new IllegalArgumentException("Invalid certificate file");
        }
    }

    private static void storeServerCertificates(QuicClientConnection quicConnection, String serverCertificatesFile) throws IOException {
        List<X509Certificate> serverCertificateChain = quicConnection.getServerCertificateChain();
        if (! serverCertificatesFile.endsWith(".pem")) {
            serverCertificatesFile += ".pem";
        }
        PrintStream out = new PrintStream(new FileOutputStream(new File(serverCertificatesFile)));
        for (X509Certificate cert: serverCertificateChain) {
            out.println("-----BEGIN CERTIFICATE-----");
            try {
                out.print(new String(Base64.getMimeEncoder().encode(cert.getEncoded())));
            } catch (CertificateEncodingException e) {
                throw new IOException(e.getMessage());
            }
            out.println("\n-----END CERTIFICATE-----");
            out.println("\n");
        }
        out.close();
    }

    private static void storeNewSessionTickets(QuicClientConnection quicConnection, String baseFilename) {
        if (quicConnection.getNewSessionTickets().isEmpty()) {
            // Wait a little, receiver thread might still be busy processing messages.
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
            }

            if (quicConnection.getNewSessionTickets().isEmpty()) {
                System.out.println("There are new new session tickets to store.");
            }
        }

        quicConnection.getNewSessionTickets().stream().forEach(ticket -> storeNewSessionTicket(ticket, baseFilename));
    }

    private static void storeNewSessionTicket(NewSessionTicket ticket, String baseFilename) {
        int maxFiles = 100;
        File savedSessionTicket = new File(baseFilename + ".bin");
        int i = 1;
        while (i <= maxFiles && savedSessionTicket.exists()) {
            savedSessionTicket = new File(baseFilename + i + ".bin");
            i++;
        }
        if (i > maxFiles) {
            System.out.println("Cannot store ticket: too many files with base name '" + baseFilename + "' already exist.");
            return;
        }
        try {
            Files.write(savedSessionTicket.toPath(), ticket.serialize(), StandardOpenOption.CREATE);
        } catch (IOException e) {
            System.err.println("Saving new session ticket failed: " + e);
        }
    }

    public static void doHttp09Request(QuicConnection quicConnection, String requestPath, String outputFile) throws IOException {
        doHttp09Request(quicConnection, requestPath, null, outputFile);
    }

    public static void doHttp09Request(QuicConnection quicConnection, String requestPath, QuicStream httpStream, String outputFile) throws IOException {
        if (httpStream == null) {
            boolean bidirectional = true;
            httpStream = quicConnection.createStream(bidirectional);
            httpStream.getOutputStream().write(("GET " + requestPath + "\r\n").getBytes());
            httpStream.getOutputStream().close();
        }

        if (outputFile != null) {
            FileOutputStream out;
            if (new File(outputFile).isDirectory()) {
                String fileName = requestPath;
                if (fileName.equals("/")) {
                    fileName = "index";
                }
                out = new FileOutputStream(new File(outputFile, fileName));
            }
            else {
                out = new FileOutputStream(outputFile);
            }
            httpStream.getInputStream().transferTo(out);
        }
        else {
            // Wait a little to let logger catch up, so output is printed nicely after all the handshake logging....
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {}

            BufferedReader input = new BufferedReader(new InputStreamReader(httpStream.getInputStream()));
            String line;
            System.out.println("Server returns: ");
            while ((line = input.readLine()) != null) {
                System.out.println(line);
            }
        }
    }

    public static void usage() {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.setWidth(79);
        helpFormatter.printHelp("kwik <host>:<port> OR kwik <host> <port> \tOR kwik http[s]://host:port[/path]", cmdLineOptions);
    }
}
