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

import java.io.*;

public class InteractiveShell {

    private final QuicConnection quicConnection;
    private boolean running;

    public InteractiveShell(QuicConnection quicConnection) {
        this.quicConnection = quicConnection;
    }

    public void start() {
        BufferedReader in = new BufferedReader(new InputStreamReader((System.in)));
        try {
            System.out.println("\nThis is the KWIK interactive shell. Type a command or 'help'.");
            prompt();

            running = true;
            while (running) {
                String cmdLine = in.readLine();
                if (! cmdLine.isBlank()) {
                    String cmd = cmdLine.split(" ")[0];
                    try {
                        switch (cmd) {
                            case "ping":
                                sendPing();
                                break;
                            case "help":
                                help();
                                break;
                            case "quit":
                                quit();
                                break;
                            default:
                                unknown();
                        }
                    }
                    catch (Exception error) {
                        error(error);
                    }
                }
                if (running) {
                    prompt();
                }
            }
        } catch (IOException e) {
            System.out.println("Error: " + e);
        }
    }

    private void help() {
        System.out.println("available commands: ping, quit");
    }

    private void quit() {
        running = false;
    }

    private void unknown() {
        System.out.println("unknown command");
    }

    private void sendPing() {
        quicConnection.ping();
    }

    private void error(Exception error) {
        System.out.println("error: " + error.getMessage());
    }

    private void prompt() {
        System.out.print("\n> ");
        System.out.flush();
    }
}
