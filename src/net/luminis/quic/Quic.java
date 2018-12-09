package net.luminis.quic;

import java.io.IOException;

/**
 * Set up a QUIC connection with a QUIC server.
 */
public class Quic {

    public static void main(String[] args) {
        if (args.length < 2) {
            usage();
        }
        else {
            Version quicVersion = Version.IETF_draft_16;
            String host = null;
            int port = -1;
            try {
                int index = 0;
                if (args[index].startsWith("-")) {
                    quicVersion = parseVersionArg(args[index]);
                    index++;
                }
                host = args[index++];
                port = Integer.parseInt(args[index++]);
            }
            catch (NumberFormatException e) {
                usage();
                return;
            }
            catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                usage();
                return;
            }

            try {
                new QuicConnection(host, port, quicVersion).connect();
            } catch (IOException e) {
                System.out.println("Got IO error: " + e);
            }
        }
    }

    private static Version parseVersionArg(String arg) throws Exception {
        switch (arg) {
            case "-14":
                return Version.IETF_draft_14;
            case "-15":
                return Version.IETF_draft_15;
            case "-16":
                return Version.IETF_draft_16;
            default:
                throw new Exception("Unsupported version argument");
        }
    }

    public static void usage() {
        System.out.println("Usage: Quic <host> <port>");
    }
}
