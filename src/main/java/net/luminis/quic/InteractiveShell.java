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

import net.luminis.tls.ByteUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;


public class InteractiveShell {

    private final QuicConnection quicConnection;
    private final Map<String, Consumer<String>> commands;
    private boolean running;
    private Map<String, String> history;

    public InteractiveShell(QuicConnection quicConnection) {
        this.quicConnection = quicConnection;
        commands = new HashMap<>();
        history = new LinkedHashMap<>();
        setupCommands();
    }

    private void setupCommands() {
        commands.put("help", this::help);
        commands.put("quit", this::quit);
        commands.put("ping", this::sendPing);
        commands.put("cids_new", this::newConnectionIds);
        commands.put("cids_next", this::nextDestinationConnectionId);
        commands.put("cids_show", this::printConnectionIds);
        commands.put("!!", this::repeatLastCommand);
    }

    private void repeatLastCommand(String arg) {
        if (history.size() > 0) {
            Map.Entry<String, String> lastCommand = history.entrySet().stream().reduce((first, second) -> second).orElse(null);
            commands.get(lastCommand.getKey()).accept(lastCommand.getValue());
        }
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
                    List<String> matchingCommands = commands.keySet().stream().filter(command -> command.startsWith(cmd)).collect(Collectors.toList());
                    if (matchingCommands.size() == 1) {
                        String matchingCommand = matchingCommands.get(0);
                        Consumer<String> commandFunction = commands.get(matchingCommand);
                        try {
                            String commandArgs = cmdLine.substring(cmd.length()).trim();
                            commandFunction.accept(commandArgs);
                            if (!matchingCommand.startsWith("!")) {
                                history.put(matchingCommand, commandArgs);
                            }
                        } catch (Exception error) {
                            error(error);
                        }
                    } else {
                        unknown();
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


    private void newConnectionIds(String arg) {
        byte[][] newConnectionIds = quicConnection.newConnectionIds(3);
        System.out.println("Generated new (source) connection id's: " +
                Arrays.stream(newConnectionIds)
                        .map(cid -> ByteUtils.bytesToHex(cid))
                        .collect(Collectors.joining(", ")));
    }

    private void printConnectionIds(String arg) {
        System.out.println("Current source connection id: " + ByteUtils.bytesToHex(quicConnection.getSourceConnectionId()));
        System.out.println("Current destination connection id: " + ByteUtils.bytesToHex(quicConnection.getDestinationConnectionId()));
        System.out.println("Available destination connection id's:");
        quicConnection.getDestinationConnectionIds().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> System.out.println(entry.getKey() + ": " + ByteUtils.bytesToHex(entry.getValue())));
    }

    private void nextDestinationConnectionId(String arg) {
        byte[] newConnectionId = quicConnection.nextDestinationConnectionId();
        System.out.println("Switched to next destination connection id: " + ByteUtils.bytesToHex(newConnectionId));
    }

    private void help(String arg) {
        System.out.println("available commands: " + commands.keySet().stream().sorted().collect(Collectors.joining(", ")));
    }

    private void quit(String arg) {
        running = false;
    }

    private void unknown() {
        System.out.println("unknown command");
    }

    private void sendPing(String arg) {
        quicConnection.ping();
    }

    private void error(Exception error) {
        System.out.println("error: " + error.getMessage());
    }

    private void prompt() {
        System.out.print("> ");
        System.out.flush();
    }
}
