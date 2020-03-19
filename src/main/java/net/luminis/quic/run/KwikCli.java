/*
 * Copyright © 2019, 2020 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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
import net.luminis.quic.log.FileLogger;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.stream.QuicStream;
import net.luminis.tls.NewSessionTicket;
import org.apache.commons.cli.*;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Command line interface for Kwik
 */
public class KwikCli {

    private static Options cmdLineOptions;

    public static void main(String[] rawArgs) throws ParseException {
        cmdLineOptions = new Options();
        cmdLineOptions.addOption("l", "log", true, "logging options: [pdrcsiRSD]: " +
                "(p)ackets received/sent, (d)ecrypted bytes, (r)ecovery, (c)ongestion control, (s)tats, (i)nfo, (R)aw bytes, (S)ecrets, (D)ebug; default is \"ip\", use (n)one to disable");
        cmdLineOptions.addOption("h", "help", false, "show help");
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
        cmdLineOptions.addOption(null, "secrets", true, "write secrets to file (Wireshark format)");
        cmdLineOptions.addOption("v", "version", false, "show Kwik version");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(cmdLineOptions, rawArgs);

        if (cmd.hasOption("v")) {
            System.out.println("Kwik build nr: " + getVersion());
            System.exit(0);
        }

        List<String> args = cmd.getArgList();
        if (args.size() == 0) {
            usage();
            return;
        }

        QuicConnectionImpl.Builder builder = QuicConnectionImpl.newBuilder();
        String http09Request = null;
        if (args.size() == 1) {
            String arg = args.get(0);
            try {
                if (arg.startsWith("http://") || arg.startsWith("https://")) {
                    try {
                        URL url = new URL(arg);
                        builder.uri(url.toURI());
                        if (!url.getPath().isEmpty()) {
                            http09Request = url.getPath();
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
        logger.logPackets(true);
        logger.logInfo(true);
        builder.logger(logger);

        if (cmd.hasOption('l')) {
            String logArg = cmd.getOptionValue('l', "ip");

            if (logArg.contains("n")) {
                logger.logRaw(false);
                logger.logDecrypted(false);
                logger.logSecrets(false);
                logger.logPackets(false);
                logger.logInfo(false);
                logger.logDebug(false);
                logger.logStats(false);
            }
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
            if (logArg.contains("s")) {
                logger.logStats(true);
            }
            if (logArg.contains("D")) {
                logger.logDebug(true);
            }
        }

        Version quicVersion = Version.getDefault();
        if (cmd.hasOption("reservedVersion")) {
            quicVersion = Version.reserved_1;
        }
        builder.version​(quicVersion);

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

        if (cmd.hasOption("H")) {
            http09Request = cmd.getOptionValue("H");
            if (http09Request == null) {
                usage();
                System.exit(1);
            }
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
                NewSessionTicket sessionTicket = NewSessionTicket.deserialize(ticketData);
                builder.sessionTicket(sessionTicket);
            } catch (IOException e) {
                System.err.println("Error while reading session ticket file.");
            }
        }

        if (cmd.hasOption("T")) {
            logger.useRelativeTime(true);
        }

        boolean interactiveMode = cmd.hasOption("i");

        try {
            if (interactiveMode) {
                new InteractiveShell(builder, alpn).start();
            }
            else {
                QuicConnection quicConnection = builder.build();
                if (alpn == null) {
                    quicConnection.connect(connectionTimeout * 1000);
                }
                else {
                    quicConnection.connect(connectionTimeout * 1000, alpn, null);
                }

                if (keepAliveTime > 0) {
                    quicConnection.keepAlive(keepAliveTime);
                }
                if (http09Request != null) {
                    doHttp09Request(quicConnection, http09Request, outputFile);
                } else {
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

        if (!interactiveMode && http09Request == null && keepAliveTime == 0) {
            System.out.println("This was quick, huh? Next time, consider using --http09 or --keepAlive argument.");
        }
    }

    private static void storeNewSessionTickets(QuicConnection quicConnection, String baseFilename) {
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

    public static void doHttp09Request(QuicConnection quicConnection, String http09Request, String outputFile) throws IOException {
        if (! http09Request.startsWith("/")) {
            http09Request = "/" + http09Request;
        }
        boolean bidirectional = true;
        QuicStream quicStream = quicConnection.createStream(bidirectional);
        quicStream.getOutputStream().write(("GET " + http09Request + "\r\n").getBytes());
        quicStream.getOutputStream().close();

        // Wait a little to let logger catch up, so output is printed nicely after all the handshake logging....
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {}

        if (outputFile != null) {
            FileOutputStream out;
            if (new File(outputFile).isDirectory()) {
                String fileName = http09Request;
                if (fileName.equals("/")) {
                    fileName = "index";
                }
                out = new FileOutputStream(new File(outputFile, fileName));
            }
            else {
                out = new FileOutputStream(outputFile);
            }
            quicStream.getInputStream().transferTo(out);
        }
        else {
            BufferedReader input = new BufferedReader(new InputStreamReader(quicStream.getInputStream()));
            String line;
            System.out.println("Server returns: ");
            while ((line = input.readLine()) != null) {
                System.out.println(line);
            }
        }
    }

    static String getVersion() {
        InputStream in = QuicConnection.class.getResourceAsStream("version.properties");
        if (in != null) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
                return reader.readLine();
            } catch (IOException e) {
                return null;
            }
        }
        else return "dev";
    }

    public static void usage() {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.setWidth(79);
        helpFormatter.printHelp("kwik <host>:<port> OR kwik <host> <port> \tOR kwik http[s]://host:port[/path]", cmdLineOptions);
    }
}
