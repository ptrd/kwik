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
        cmdLineOptions.addOption("l", "log", true, "logging options: [pdrsiSD]: " +
                "(p)ackets received/sent, (d)ecrypted bytes, (r)aw bytes, (s)tats, (i)nfo, (S)ecrets, (D)ebug; default is \"is\", use (n)one to disable");
        cmdLineOptions.addOption("h", "help", false, "show help");
        cmdLineOptions.addOption("14", "use Quic version IETF_draft_14");
        cmdLineOptions.addOption("15", "use Quic version IETF_draft_15");
        cmdLineOptions.addOption("16", "use Quic version IETF_draft_16");
        cmdLineOptions.addOption("17", "use Quic version IETF_draft_17");
        cmdLineOptions.addOption("18", "use Quic version IETF_draft_18");
        cmdLineOptions.addOption("c", "connectionTimeout", true, "connection timeout in seconds");
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

        Logger logger = new Logger();
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
            if (logArg.contains("r")) {
                logger.logRaw(true);
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
        if (cmd.hasOption("18")) {
            quicVersion = Version.IETF_draft_18;
        }
        else if (cmd.hasOption("17")) {
            quicVersion = Version.IETF_draft_17;
        }
        else if (cmd.hasOption("16")) {
            quicVersion = Version.IETF_draft_16;
        }
        else if (cmd.hasOption("15")) {
            quicVersion = Version.IETF_draft_15;
        }
        else if (cmd.hasOption("14")) {
            quicVersion = Version.IETF_draft_14;
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

        if (cmd.hasOption("T")) {
            logger.useRelativeTime(true);
        }

        try {
            QuicConnection quicConnection = new QuicConnection(host, port, quicVersion, logger);

            quicConnection.connect(connectionTimeout * 1000);

            boolean bidirectional = true;
            QuicStream quicStream = quicConnection.createStream(bidirectional);
            quicStream.getOutputStream().write("GET /index.html\r\n".getBytes());
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

            quicConnection.close();

            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {}

            System.out.println("Terminating Quic");

        }
        catch (IOException e) {
            System.out.println("Got IO error: " + e);
        }
        catch (VersionNegationFailure e) {
            System.out.println("Client and server could not agree on a compatible QUIC version.");
        }
    }

    public static void usage() {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.setWidth(79);
        helpFormatter.printHelp("quic <host>:<port> OR quic <host> <port>", cmdLineOptions);
    }
}
