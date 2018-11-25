package net.luminis.quic;

import java.io.IOException;

/**
 * Set up a QUIC connection with a QUIC server.
 */
public class Quic {

    public static void main(String[] args) {
        if (args.length != 2) {
            usage();
        }
        else {
            try {
                String host = args[0];
                int port = Integer.parseInt(args[1]);
                new QuicConnection(host, port).connect();
            }
            catch (NumberFormatException e) {
                usage();
            } catch (IOException e) {
                System.out.println("Got IO error: " + e);
            }

        }
    }

    public static void usage() {
        System.out.println("Usage: Quic <host> <port>");
    }
}
