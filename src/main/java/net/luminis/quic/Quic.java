/*
 * Copyright © 2019 Peter Doornbosch
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
package net.luminis.quic;

import org.apache.commons.cli.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

/**
 * Set up a QUIC connection with a QUIC server.
 */
public class Quic {

    private static Options cmdLineOptions;

    public static void main(String[] rawArgs) throws ParseException {
        cmdLineOptions = new Options();
        cmdLineOptions.addOption("l", "log", true, "logging options: [pdrsiRSD]: " +
                "(p)ackets received/sent, (d)ecrypted bytes, (r)ecovery, (s)tats, (i)nfo, (R)aw bytes, (S)ecrets, (D)ebug; default is \"is\", use (n)one to disable");
        cmdLineOptions.addOption("h", "help", false, "show help");
        cmdLineOptions.addOption("17", "use Quic version IETF_draft_17");
        cmdLineOptions.addOption("18", "use Quic version IETF_draft_18");
        cmdLineOptions.addOption("19", "use Quic version IETF_draft_19");
        cmdLineOptions.addOption("20", "use Quic version IETF_draft_20");
        cmdLineOptions.addOption("22", "use Quic version IETF_draft_22");
        cmdLineOptions.addOption("c", "connectionTimeout", true, "connection timeout in seconds");
        cmdLineOptions.addOption("i", "interactive", false, "start interactive shell");
        cmdLineOptions.addOption("k", "keepAlive", true, "connection keep alive time in seconds");
        cmdLineOptions.addOption("L", "logFile", true, "file to write log message too");
        cmdLineOptions.addOption("H", "http09", true, "send HTTP 0.9 request, arg is path, e.g. '/index.html'");
        cmdLineOptions.addOption("T", "relativeTime", false, "log with time (in seconds) since first packet");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(cmdLineOptions, rawArgs);

        String host = null;
        int port = -1;

        List<String> args = cmd.getArgList();
        if (args.size() == 0) {
            usage();
            return;
        }
        if (args.size() == 1) {
            String arg = args.get(0);
            if (arg.contains(":")) {
                host = arg.split(":")[0];
                try {
                    port = Integer.parseInt(arg.split(":")[1]);
                }
                catch (NumberFormatException e) {
                    usage();
                    return;
                }
            }
            else {
                if (arg.matches("\\d+")) {
                    System.out.println("Error: invalid hostname (did you forget to specify an option argument?).");
                    usage();
                    return;
                }
                host = arg;
                port = 443;
            }
        }
        if (args.size() == 2) {
            host = args.get(0);
            try {
                port = Integer.parseInt(args.get(1));
            }
            catch (NumberFormatException e) {
                System.out.println("Error: invalid port number argument.");
                usage();
                return;
            }
        }
        if (args.size() > 2) {
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

        if (cmd.hasOption('l')) {
            String logArg = cmd.getOptionValue('l', "is");

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
        if (cmd.hasOption("22")) {
            quicVersion = Version.IETF_draft_22;
        }
        else if (cmd.hasOption("20")) {
            quicVersion = Version.IETF_draft_20;
        }
        else if (cmd.hasOption("19")) {
            quicVersion = Version.IETF_draft_19;
        }
        else if (cmd.hasOption("18")) {
            quicVersion = Version.IETF_draft_18;
        }
        else if (cmd.hasOption("17")) {
            quicVersion = Version.IETF_draft_17;
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

        String http09Request = null;
        if (cmd.hasOption("H")) {
            http09Request = cmd.getOptionValue("H");
            if (http09Request == null) {
                usage();
                System.exit(1);
            }
        }

        if (cmd.hasOption("T")) {
            logger.useRelativeTime(true);
        }

        boolean interactiveMode = cmd.hasOption("i");

        try {
            if (interactiveMode) {
                new InteractiveShell(host, port, quicVersion, logger).start();
            }
            else {
                QuicConnection quicConnection = new QuicConnection(host, port, quicVersion, logger);
                quicConnection.connect(connectionTimeout * 1000);

                if (keepAliveTime > 0) {
                    quicConnection.keepAlive(keepAliveTime);
                }
                if (http09Request != null) {
                    doHttp09Request(quicConnection, http09Request);
                } else {
                    if (keepAliveTime > 0) {
                        try {
                            Thread.sleep((keepAliveTime + 30) * 1000);
                        } catch (InterruptedException e) {
                        }
                    }
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
        catch (VersionNegationFailure e) {
            System.out.println("Client and server could not agree on a compatible QUIC version.");
        }

        if (!interactiveMode && http09Request == null && keepAliveTime == 0) {
            System.out.println("This was quick, huh? Next time, consider using --http09 or --keepAlive argument.");
        }
    }

    private static void doHttp09Request(QuicConnection quicConnection, String http09Request) throws IOException {
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

        BufferedReader input = new BufferedReader(new InputStreamReader(quicStream.getInputStream()));
        String line;
        System.out.println("Server returns: ");
        while ((line = input.readLine()) != null) {
            System.out.println(line);
        }
    }

    public static void usage() {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.setWidth(79);
        helpFormatter.printHelp("quic <host>:<port> OR quic <host> <port>", cmdLineOptions);
    }
}
