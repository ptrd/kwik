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
package net.luminis.quic.run;

import net.luminis.quic.QuicConnection;
import net.luminis.quic.TransportParameters;
import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.tls.ByteUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;


public class InteractiveShell {

    private final Map<String, Consumer<String>> commands;
    private boolean running;
    private Map<String, String> history;
    private final String host;
    private final int port;
    private final Version quicVersion;
    private final Logger logger;
    private final Path secretsFile;
    private final String alpn;
    private QuicConnection quicConnection;
    private TransportParameters params;

    public InteractiveShell(String host, int port, Version quicVersion, Logger logger, Path secretsFile, String alpn) {
        this.host = host;
        this.port = port;
        this.quicVersion = quicVersion;
        this.logger = logger;
        this.secretsFile = secretsFile;
        this.alpn = alpn;

        commands = new HashMap<>();
        history = new LinkedHashMap<>();
        setupCommands();

        initParams();
    }

    private void initParams() {
        params = new TransportParameters(60, 250_000, 3 , 3);
    }

    private void setupCommands() {
        commands.put("help", this::help);
        commands.put("connect", this::connect);
        commands.put("close", this::close);
        commands.put("quit", this::quit);
        commands.put("ping", this::sendPing);
        commands.put("server_params", this::printServerParams);
        commands.put("params", this::printClientParams);
        commands.put("set", this::setClientParameter);
        commands.put("cids_new", this::newConnectionIds);
        commands.put("cids_next", this::nextDestinationConnectionId);
        commands.put("cids_show", this::printConnectionIds);
        commands.put("udp_rebind", this::changeUdpPort);
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
                        unknown(cmd);
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

    private void connect(String arg) {
        int connectionTimeout = 3000;
        if (arg != null && !arg.isBlank()) {
            try {
                connectionTimeout = Integer.parseInt(arg);
                if (connectionTimeout < 100) {
                    System.out.println("Connection timeout must be at least 100 ms");
                    return;
                }
            } catch (NumberFormatException notANumber) {
                System.out.println("Connection timeout argument must be an integer value");
                return;
            }
        }

        try {
            quicConnection = new QuicConnection(host, port, null, quicVersion, logger, secretsFile);
            if (alpn == null) {
                quicConnection.connect(connectionTimeout, params);
            }
            else {
                quicConnection.connect(connectionTimeout, alpn, params);
            }
            System.out.println("Ok, connected to " + host + "\n");
        } catch (IOException e) {
            System.out.println("\nError: " + e);
        }
    }

    private void close(String arg) {
        if (quicConnection != null) {
            quicConnection.close();
        }
    }

    private void newConnectionIds(String args) {
        int newConnectionIdCount = 1;
        int retirePriorTo = 0;  // i.e. no retirement.

        if (!args.isEmpty()) {
            try {
                Object[] intArgs = Stream.of(args.split(" +")).map(arg -> Integer.parseInt(arg)).toArray();
                newConnectionIdCount = (int) intArgs[0];
                if (intArgs.length > 1) {
                    retirePriorTo = (int) intArgs[1];
                }
            } catch (NumberFormatException notANumber) {
                System.out.println("Expected arguments: [<number of new ids>] [<sequence number to retire cids prior to>]");
                return;
            }
        }

        byte[][] newConnectionIds = quicConnection.newConnectionIds(newConnectionIdCount, retirePriorTo);
        System.out.println("Generated new (source) connection id's: " +
                Arrays.stream(newConnectionIds)
                        .map(cid -> ByteUtils.bytesToHex(cid))
                        .collect(Collectors.joining(", ")));
    }

    private void printConnectionIds(String arg) {
        System.out.println("Current source connection id: " + ByteUtils.bytesToHex(quicConnection.getSourceConnectionId()));
        System.out.println("Generated source connection id's:");
        quicConnection.getSourceConnectionIds().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> System.out.println(entry.getKey() + ": " + ByteUtils.bytesToHex(entry.getValue())));
        System.out.println("Current destination connection id: " + ByteUtils.bytesToHex(quicConnection.getDestinationConnectionId()));
        System.out.println("Available destination connection id's:");
        quicConnection.getDestinationConnectionIds().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> System.out.println(entry.getKey() + ": " + ByteUtils.bytesToHex(entry.getValue())));
    }

    private void nextDestinationConnectionId(String arg) {
        byte[] newConnectionId = quicConnection.nextDestinationConnectionId();
        if (newConnectionId != null) {
            System.out.println("Switched to next destination connection id: " + ByteUtils.bytesToHex(newConnectionId));
        }
        else {
            System.out.println("Cannot switch to next destination connect id, because there is none available");
        }
    }

    private void changeUdpPort(String args) {
        quicConnection.changeAddress();
    }

    private void help(String arg) {
        System.out.println("available commands: " + commands.keySet().stream().sorted().collect(Collectors.joining(", ")));
    }

    private void quit(String arg) {
        running = false;
    }

    private void unknown(String cmd) {
        System.out.println("unknown command: " + cmd);
    }

    private void sendPing(String arg) {
        quicConnection.ping();
    }

    private void printClientParams(String arg) {
        System.out.print("Client transport parameters: ");
        if (quicConnection != null) {
            System.out.println(quicConnection.getTransportParameters());
        }
        else {
            System.out.println(params);
        }
    }

    private void setClientParameter(String argLine) {
        String[] args = argLine.split("\\s+");
        if (args.length == 2) {
            String name = args[0];
            String value = args[1];
            setClientParameter(name, value);
        } else {
            System.out.println("Incorrect parameters; should be <name> <value>");
        }
    }

    private void setClientParameter(String name, String value) {
        switch (name) {
            case "idle":
                params.setIdleTimeout(toInt(value));
                break;
            case "cids":
                params.setActiveConnectionIdLimit(toInt(value));
                break;
            default:
                System.out.println("Parameter must be one of:");
                System.out.println("- idle (idle timeout)");
                System.out.println("- cids (active connection id limit)");
        }
    }

    private void printServerParams(String arg) {
        if (quicConnection != null) {
            TransportParameters parameters = quicConnection.getPeerTransportParameters();
            System.out.println("Server transport parameters: " + parameters);
        }
        else {
            System.out.println("Server transport parameters still unknown (no connection)");
        }
    }

    private void error(Exception error) {
        System.out.println("error: " + error);
    }

    private void prompt() {
        System.out.print("> ");
        System.out.flush();
    }

    private Integer toInt(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            System.out.println("Error: value not an integer; using 0");
            return 0;
        }
    }
}
