/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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

import net.luminis.quic.TransportParameters;
import net.luminis.quic.cid.ConnectionIdStatus;
import net.luminis.quic.core.QuicClientConnectionImpl;
import net.luminis.quic.core.Receiver;
import net.luminis.tls.util.ByteUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;


public class InteractiveShell {

    private final Map<String, Consumer<String>> commands;
    private boolean running;
    private Map<String, String> history;
    private final QuicClientConnectionImpl.Builder builder;
    private final String alpn;
    private QuicClientConnectionImpl quicConnection;
    private TransportParameters params;
    private KwikCli.HttpVersion httpVersion;
    private HttpClient httpClient;
    private CompletableFuture<HttpResponse<Path>> currentHttpGetResult;

    public InteractiveShell(QuicClientConnectionImpl.Builder builder, String alpn, KwikCli.HttpVersion httpVersion) {
        Objects.requireNonNull(builder);
        Objects.requireNonNull(alpn);
        this.builder = builder;
        this.alpn = alpn;
        this.httpVersion = httpVersion;

        commands = new LinkedHashMap<>();
        history = new LinkedHashMap<>();
        setupCommands();

        initParams();
    }

    private void initParams() {
        params = new TransportParameters(60, 250_000, 3 , 3);
    }

    private void setupCommands() {
        commands.put("help", this::help);
        commands.put("set", this::setClientParameter);
        commands.put("scid_length", this::setScidLength);
        commands.put("connect", this::connect);
        commands.put("close", this::close);
        commands.put("get", this::httpGet);
        commands.put("stop", this::httpStop);
        commands.put("ping", this::sendPing);
        commands.put("params", this::printClientParams);
        commands.put("server_params", this::printServerParams);
        commands.put("cid_new", this::newConnectionIds);
        commands.put("cid_next", this::nextDestinationConnectionId);
        commands.put("cid_list", this::printConnectionIds);
        commands.put("cid_retire", this::retireConnectionId);
        commands.put("udp_rebind", this::changeUdpPort);
        commands.put("update_keys", this::updateKeys);
        commands.put("statistics", this::printStatistics);
        commands.put("!!", this::repeatLastCommand);
        commands.put("quit", this::quit);
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
            builder.connectTimeout(Duration.ofMillis(connectionTimeout));
            quicConnection = (QuicClientConnectionImpl) builder.build();
            quicConnection.connect(alpn, params, null);
            System.out.println("Ok, connected to " + quicConnection.getUri() + "\n");
        } catch (IOException e) {
            System.out.println("\nError: " + e);
        }
    }

    private void close(String arg) {
        if (quicConnection != null) {
            quicConnection.close();
        }
    }

    private void httpGet(String arg) {
        if (quicConnection == null) {
            System.out.println("Error: no connected");
            return;
        }

        try {
            if (httpClient == null) {
                httpClient = KwikCli.createHttpClient(httpVersion, quicConnection, false);
            }
            InetSocketAddress serverAddress = quicConnection.getServerAddress();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI("https", null, serverAddress.getHostName(), serverAddress.getPort(), arg, null, null))
                    .build();

            final Instant start = Instant.now();
            CompletableFuture<HttpResponse<Path>> sendResult = httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofFile(createNewFile(arg).toPath()));
            sendResult.thenAccept(response -> {
                Instant done = Instant.now();
                Duration duration = Duration.between(start, done);
                String speed;
                try {
                    long size = Files.size(response.body());
                    speed = String.format("%.2f", ((float) size) / duration.toMillis() / 1000);
                }
                catch (IOException e) {
                    speed = "?";
                }
                System.out.println(String.format("Get requested finished in %.2f sec (%s MB/s) : %s", ((float) duration.toMillis())/1000, speed, response));
            });
            currentHttpGetResult = sendResult;
        }
        catch (IOException | URISyntaxException e) {
            System.out.println("Error: " + e);
        }
    }

    private void httpStop(String arg) {
        currentHttpGetResult.cancel(true);
    }

    private File createNewFile(String baseName) throws IOException {
        if (baseName.startsWith("/") && baseName.length() > 1) {
            baseName = baseName.substring(1);
        }
        baseName = baseName.replace('/', '_');
        File file = new File(baseName + ".dat");
        if (! file.exists()) {
            return file;
        }
        for (int i = 0; i < 1000; i++) {
            file = new File(baseName + i + ".dat");
            if (! file.exists()) {
                return file;
            }
        }
        throw new IOException("Cannot create output file '" + baseName + ".dat" + "'");
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
        System.out.println("Source (client) connection id's:");
        quicConnection.getSourceConnectionIds().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> System.out.println(toString(entry.getValue().getConnectionIdStatus()) + " " +
                        entry.getKey() + ": " + ByteUtils.bytesToHex(entry.getValue().getConnectionId())));
        System.out.println("Destination (server) connection id's:");
        quicConnection.getDestinationConnectionIds().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> System.out.println(toString(entry.getValue().getConnectionIdStatus()) + " " +
                        entry.getKey() + ": " + ByteUtils.bytesToHex(entry.getValue().getConnectionId())));
    }

    private String toString(ConnectionIdStatus connectionIdStatus) {
        switch (connectionIdStatus) {
            case NEW: return " ";
            case IN_USE: return "*";
            case USED: return ".";
            case RETIRED: return "x";
            default:
                // Impossible
                throw new RuntimeException("");
        }
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

    private void retireConnectionId(String arg) {
        quicConnection.retireDestinationConnectionId(toInt(arg));
    }

    private void changeUdpPort(String args) {
        quicConnection.changeAddress();
    }

    private void help(String arg) {
        System.out.println("available commands: " + commands.keySet().stream().collect(Collectors.joining(", ")));
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

    private void printParams(String arg) {
        TransportParameters parameters = quicConnection.getPeerTransportParameters();
        System.out.println("Server idle time: " + parameters.getMaxIdleTimeout());
        System.out.println("Server initial max data: " + parameters.getInitialMaxData());
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
            System.out.println("Incorrect parameters; should be <transport parameter name> <value>.");
            System.out.println("Supported parameters: ");
            printSupportedParameters();
        }
    }

    private void printSupportedParameters() {
        System.out.println("- idle (idle timeout)");
        System.out.println("- cids (active connection id limit)");
        System.out.println("- maxstreamdata (receive buffer size)");
        System.out.println("- payload (max udp payload)");
    }

    private void setClientParameter(String name, String value) {
        switch (name) {
            case "idle":
                params.setMaxIdleTimeout(toInt(value));
                break;
            case "cids":
                params.setActiveConnectionIdLimit(toInt(value));
                break;
            case "maxStreamData":
            case "maxstreamdata":
                params.setInitialMaxStreamData(toLong(value));
                break;
            case "payload":
                params.setMaxUdpPayloadSize(toInt(value));
                if (toInt(value) > Receiver.MAX_DATAGRAM_SIZE) {
                    System.out.println(String.format("Warning: client will read at most %d datagram bytes", Receiver.MAX_DATAGRAM_SIZE));
                }
                break;
            default:
                System.out.println("Parameter must be one of:");
                printSupportedParameters();
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

    private void printStatistics(String arg) {
        if (quicConnection != null) {
            System.out.println(quicConnection.getStats());
        }
    }

    private void setScidLength(String arg) {
        builder.connectionIdLength(toInt(arg));
    }

    private void updateKeys(String arg) {
        quicConnection.updateKeys();
        quicConnection.ping();
    }

    private void error(Exception error) {
        System.out.println("error: " + error);
        error.printStackTrace();
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

    private Long toLong(String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            System.out.println("Error: value not an integer; using 0");
            return 0L;
        }
    }
}
