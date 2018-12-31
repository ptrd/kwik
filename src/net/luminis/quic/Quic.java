package net.luminis.quic;

import org.apache.commons.cli.*;

import java.io.IOException;
import java.util.List;

/**
 * Set up a QUIC connection with a QUIC server.
 */
public class Quic {

    private static Options cmdLineOptions;

    public static void main(String[] rawArgs) throws ParseException {
        cmdLineOptions = new Options();
        cmdLineOptions.addOption("l", "log", true, "logging options: [Drdspi]");
        cmdLineOptions.addOption("14", "Use Quic version IETF_draft_14");
        cmdLineOptions.addOption("15", "Use Quic version IETF_draft_15");
        cmdLineOptions.addOption("16", "Use Quic version IETF_draft_16");

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
            String logArg = cmd.getOptionValue('l', "i");

            if (logArg.contains("n")) {
                logger.logRaw(false);
                logger.logDecrypted(false);
                logger.logSecrets(false);
                logger.logPackets(false);
                logger.logInfo(false);
                logger.logDebug(false);
            }
            if (logArg.contains("r")) {
                logger.logRaw(true);
            }
            if (logArg.contains("d")) {
                logger.logDecrypted(true);
            }
            if (logArg.contains("s")) {
                logger.logSecrets(true);
            }
            if (logArg.contains("p")) {
                logger.logPackets(true);
            }
            if (logArg.contains("i")) {
                logger.logInfo(true);
            }
            if (logArg.contains("D")) {
                logger.logDebug(true);
            }
        }

        Version quicVersion = Version.IETF_draft_16;
        if (cmd.hasOption("16")) {
            quicVersion = Version.IETF_draft_16;
        }
        else if (cmd.hasOption("15")) {
            quicVersion = Version.IETF_draft_15;
        }
        else if (cmd.hasOption("14")) {
            quicVersion = Version.IETF_draft_14;
        }

        try {
            new QuicConnection(host, port, quicVersion, logger).connect();
        } catch (IOException e) {
            System.out.println("Got IO error: " + e);
        }
    }

    public static void usage() {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.printHelp("quic <host>:<port>", cmdLineOptions);
    }
}
