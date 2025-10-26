/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.cli;

import org.apache.commons.cli.*;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.core.KwikVersion;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicSessionTicket;
import tech.kwik.core.impl.QuicClientConnectionImpl;
import tech.kwik.core.impl.QuicSessionTicketImpl;
import tech.kwik.core.impl.VersionNegotiationFailure;
import tech.kwik.core.log.FileLogger;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.SysOutLogger;
import tech.kwik.h09.client.Http09Client;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static tech.kwik.core.impl.QuicClientConnectionImpl.DEFAULT_MAX_STREAM_DATA;
import static tech.kwik.core.impl.QuicClientConnectionImpl.MIN_RECEIVER_BUFFER_SIZE;

/**
 * Command line interface for Kwik client.
 */
public class KwikCli {

    private static String DEFAULT_LOG_ARGS = "wip";
    private static Options cmdLineOptions;

    private String newSessionTicketsFilename;
    private boolean useZeroRtt;
    private String serverCertificatesFile;
    private int keepAliveTime;

    public enum HttpVersion {
        HTTP09,
        HTTP3
    }

    private HttpVersion httpVersion;
    private String alpn;
    private Logger logger;


    public void run(String[] rawArgs) throws Exception {
        CommandLine cmd = getCommandLine(rawArgs);

        boolean interactiveMode = cmd.hasOption("i");

        QuicClientConnection.Builder connectionBuilder = createConnectionBuilder(interactiveMode);

        String httpRequestPath = processUrlArgs(cmd, connectionBuilder);

        if (cmd.hasOption("preferIPv6")) {
            connectionBuilder.preferIPv6();
        }

        processCipherArgs(cmd, connectionBuilder);

        if (cmd.hasOption("noCertificateCheck")) {
            connectionBuilder.noServerCertificateCheck();
        }
        if (cmd.hasOption("trustStore")) {
            String password = cmd.hasOption("trustStorePassword")? cmd.getOptionValue("trustStorePassword"): "";
            connectionBuilder.customTrustStore(KeyStore.getInstance(new File(cmd.getOptionValue("trustStore")), password.toCharArray()));
        }

        if (cmd.hasOption("saveServerCertificates")) {
            serverCertificatesFile = cmd.getOptionValue("saveServerCertificates");
        }

        processLoggerArgs(cmd, connectionBuilder);

        processVersionArgs(cmd, connectionBuilder);

        httpVersion = determineHttpVersion();

        alpn = determineAlpn(cmd);

        processConnectTimeoutArgs(cmd, connectionBuilder);

        processKeepAliveArg(cmd);

        httpRequestPath = extractHttpRequestPath(cmd, connectionBuilder, httpRequestPath);

        useZeroRtt = cmd.hasOption("Z");
        if (useZeroRtt && httpRequestPath == null) {
            throw new IllegalArgumentException("Option --use0RTT requires option --http");
        }

        String outputFile = extractOutputFile(cmd);

        processSecretsArgs(cmd, connectionBuilder);

        processSessionTicketSaveArg(cmd, connectionBuilder);

        boolean useSessionTicket = processSessionTicketArg(cmd, connectionBuilder);

        if (useZeroRtt && !useSessionTicket) {
            throw new IllegalArgumentException("Option --use0RTT requires option --sessionTicket");
        }

        processClientCertificateArgs(cmd, connectionBuilder);

        processQuantumReadinessTestArg(cmd, connectionBuilder);

        processInitialRttArg(cmd, connectionBuilder);

        processBufferSizeArg(cmd, connectionBuilder);

        if (httpVersion == HttpVersion.HTTP3 && useZeroRtt) {
            throw new IllegalArgumentException("Option --use0RTT is not yet supported by this HTTP3 implementation.");
        }

        try {
            if (interactiveMode) {
                new InteractiveShell((QuicClientConnectionImpl.ExtendedBuilder) connectionBuilder, alpn, httpVersion).start();
            }
            else {
                executeRequest(httpRequestPath, outputFile, connectionBuilder);
                Thread.sleep(1000);
            }

            System.out.println("Terminating Kwik");

            if (!interactiveMode && httpRequestPath == null && keepAliveTime == 0) {
                System.out.println("This was quick, huh? Next time, consider using --http09 or --keepAlive argument.");
            }
        }
        catch (IOException e) {
            System.out.println("Got IO error: " + e);
        }
        catch (VersionNegotiationFailure e) {
            System.out.println("Client and server could not agree on a compatible QUIC version.");
        }
        catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private CommandLine getCommandLine(String[] rawArgs) {
        CommandLine cmd;
        try {
            CommandLineParser parser = new DefaultParser();
            cmd = parser.parse(cmdLineOptions, rawArgs);

            if (cmd.hasOption("v")) {
                System.out.println("Kwik version: " + KwikVersion.getVersion());
                System.exit(0);
            }

            if (cmd.getArgList().isEmpty()) {
                throw new IllegalArgumentException("Missing arguments");
            }

            return cmd;
        }
        catch (ParseException argError) {
            throw new IllegalArgumentException("Invalid argument: " + argError.getMessage());
        }
    }

    private QuicClientConnection.Builder createConnectionBuilder(boolean interactiveMode) {
        if (interactiveMode) {
            return QuicClientConnectionImpl.newExtendedBuilder();
        }
        else {
            return QuicClientConnection.newBuilder();
        }
    }

    private String processUrlArgs(CommandLine cmd, QuicClientConnection.Builder builder) {
        String httpRequestPath = null;
        List<String> args = cmd.getArgList();
        if (args.size() == 1) {
            String arg = args.get(0);
            try {
                if (arg.startsWith("http://") || arg.startsWith("https://")) {
                    try {
                        URL url = new URL(arg);
                        builder.uri(url.toURI());
                        if (!url.getPath().isEmpty()) {
                            httpRequestPath = url.getPath();
                        }
                    } catch (MalformedURLException e) {
                        throw new IllegalArgumentException("Cannot parse URL '" + arg + "'");
                    }
                }
                else if (arg.contains(":")) {
                    builder.uri(new URI("//" + arg));
                }
                else {
                    if (arg.matches("\\d+")) {
                        throw new IllegalArgumentException("Invalid hostname (did you forget to specify an option argument?).");
                    }
                    builder.uri(new URI("//" + arg + ":" + 443));
                }
            }
            catch (URISyntaxException invalidUri) {
                throw new IllegalArgumentException("Cannot parse URI '" + arg + "'");
            }
        }
        else if (args.size() == 2) {
            try {
                builder.uri(new URI("//" + args.get(0) + ":" + args.get(1)));
            }
            catch (URISyntaxException invalidUri) {
                throw new IllegalArgumentException("Cannot parse URI '" + args.stream().collect(Collectors.joining(":")) + "'");
            }
        }
        else if (args.size() > 2) {
            throw new IllegalArgumentException("Too many arguments");
        }
        return httpRequestPath;
    }

    private QuicClientConnection.Builder processCipherArgs(CommandLine cmd, QuicClientConnection.Builder builder) {
        List<String> cipherOpts = List.of("aes128gcm", "aes256gcm", "chacha20");

        // Process cipher options in order, as order has meaning! (preference)
        List<Option> cipherOptions = Arrays.stream(cmd.getOptions())
                .filter(option -> option.hasLongOpt())
                .filter(option -> cipherOpts.contains(option.getLongOpt()))
                .distinct()
                .collect(Collectors.toList());

        for (Option cipherOption: cipherOptions) {
            if (cipherOption.getLongOpt().equals("aes128gcm")) {
                builder.cipherSuite(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);
            }
            if (cipherOption.getLongOpt().equals("aes256gcm")) {
                builder.cipherSuite(TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384);
            }
            if (cipherOption.getLongOpt().equals("chacha20")) {
                builder.cipherSuite(TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
            }
        }

        return builder;
    }

    private void processLoggerArgs(CommandLine cmd, QuicClientConnection.Builder builder) {
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

        String logArg = DEFAULT_LOG_ARGS;
        if (cmd.hasOption('l')) {
            logArg = cmd.getOptionValue('l', logArg);
        }

        if (!logArg.contains("n")) {
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
            if (logArg.contains("w")) {
                logger.logWarning(true);
            }
            if (logArg.contains("s")) {
                logger.logStats(true);
            }
            if (logArg.contains("D")) {
                logger.logDebug(true);
            }
        }

        if (cmd.hasOption("T")) {
            logger.useRelativeTime(true);
        }

        builder.logger(logger);
    }

    private void processVersionArgs(CommandLine cmd, QuicClientConnection.Builder builder) {
        QuicConnection.QuicVersion quicVersion = QuicConnection.QuicVersion.V1;
        QuicConnection.QuicVersion preferredVersion = null;

        if (cmd.hasOption("v1v2")) {
            quicVersion = QuicConnection.QuicVersion.V1;
            preferredVersion = QuicConnection.QuicVersion.V2;
        }
        else if (cmd.hasOption("v2")) {
            quicVersion = QuicConnection.QuicVersion.V2;
        }
        else if (cmd.hasOption("v1")) {
            quicVersion = QuicConnection.QuicVersion.V1;
        }

        builder.version(quicVersion);
        builder.preferredVersion(preferredVersion);
    }

    private HttpVersion determineHttpVersion() {
        HttpVersion httpVersion = loadHttp3ClientClass()? HttpVersion.HTTP3: HttpVersion.HTTP09;
        return httpVersion;
    }

    private String determineAlpn(CommandLine cmd) {
        String alpn;
        if (cmd.hasOption("A")) {
            alpn = cmd.getOptionValue("A", null);
            if (alpn == null) {
                throw new IllegalArgumentException("Missing argument for option -A");
            }
        }
        else {
            alpn = httpVersion == HttpVersion.HTTP3? "h3": "hq-interop";
        }
        return alpn;
    }

    private void processConnectTimeoutArgs(CommandLine cmd, QuicClientConnection.Builder builder) {
        if (cmd.hasOption("c")) {
            try {
                int connectionTimeout = Integer.parseInt(cmd.getOptionValue("c"));
                builder.connectTimeout(Duration.ofSeconds(connectionTimeout));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid value for --connectionTimeout: " + cmd.getOptionValue("c"));
            }
        }
    }

    private void processKeepAliveArg(CommandLine cmd) {
        if (cmd.hasOption("k")) {
            try {
                keepAliveTime = Integer.parseInt(cmd.getOptionValue("k"));
            }
            catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid value for --keepAlive: " + cmd.getOptionValue("k"));
            }
        }
    }

    private String extractHttpRequestPath(CommandLine cmd, QuicClientConnection.Builder builder, String defaultValue) {
        String httpRequestPath = defaultValue;
        if (cmd.hasOption("H")) {
            if (cmd.getOptionValue("H") == null) {
                throw new IllegalArgumentException("Missing argument for option -H");
            }
            else {
                httpRequestPath = cmd.getOptionValue("H");
                if (! httpRequestPath.startsWith("/")) {
                    httpRequestPath = "/" + httpRequestPath;
                }
            }
        }
        return httpRequestPath;
    }

    private String extractOutputFile(CommandLine cmd) {
        String outputFile = null;
        if (cmd.hasOption("O")) {
            outputFile = cmd.getOptionValue("O");
            if (outputFile == null) {
                throw new IllegalArgumentException("Missing argument for option -O");
            }
            if (Files.exists(Paths.get(outputFile)) && !Files.isWritable(Paths.get(outputFile))) {
                throw new IllegalArgumentException("Output file '" + outputFile + "' is not writable.");
            }
        }
        return outputFile;
    }

    private void processSecretsArgs(CommandLine cmd, QuicClientConnection.Builder builder) {
        if (cmd.hasOption("secrets")) {
            String secretsFile = cmd.getOptionValue("secrets");
            if (secretsFile == null) {
                throw new IllegalArgumentException("Missing argument for option -secrets");
            }
            if (Files.exists(Paths.get(secretsFile)) && !Files.isWritable(Paths.get(secretsFile))) {
                throw new IllegalArgumentException("Secrets file '" + secretsFile + "' is not writable.");
            }
            builder.secrets(Paths.get(secretsFile));
        }
    }

    private void processSessionTicketSaveArg(CommandLine cmd, QuicClientConnection.Builder builder) {
        if (cmd.hasOption("S")) {
            newSessionTicketsFilename = cmd.getOptionValue("S");
            if (newSessionTicketsFilename == null) {
                throw new IllegalArgumentException("Missing argument for option -S");
            }
        }
    }

    private boolean processSessionTicketArg(CommandLine cmd, QuicClientConnection.Builder builder) {
        if (cmd.hasOption("R")) {
            String sessionTicketFile = cmd.getOptionValue("R");
            if (sessionTicketFile == null) {
                throw new IllegalArgumentException("Missing argument for option -R");
            }
            if (!Files.isReadable(Paths.get(sessionTicketFile))) {
                throw new IllegalArgumentException("Session ticket file '" + sessionTicketFile + "' is not readable.");
            }
            try {
                byte[] ticketData = Files.readAllBytes(Paths.get(sessionTicketFile));
                QuicSessionTicket sessionTicket = QuicSessionTicketImpl.deserialize(ticketData);
                builder.sessionTicket(sessionTicket);
                return true;
            } catch (IOException e) {
                throw new IllegalArgumentException("Error while reading session ticket file.");
            }
        }
        else {
            return false;
        }
    }

    private void processClientCertificateArgs(CommandLine cmd, QuicClientConnection.Builder builder) {
        if (cmd.hasOption("clientCertificate") && cmd.hasOption("keyManager")) {
            throw new IllegalArgumentException("Options --clientCertificate and --keyManager should not be used together");
        }
        if (cmd.hasOption("keyManager")) {
            try {
                String keyStorePassword = cmd.hasOption("keyManagerPassword")? cmd.getOptionValue("keyManagerPassword"): "";
                KeyStore keyStore = KeyStore.getInstance(new File(cmd.getOptionValue("keyManager")), keyStorePassword.toCharArray());
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
                KeyManager keyManager = keyManagerFactory.getKeyManagers()[0];
                if (keyManager instanceof X509ExtendedKeyManager) {
                    builder.clientKeyManager((X509ExtendedKeyManager) keyManager);
                }
            }
            catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                   UnrecoverableKeyException e) {
                throw new IllegalArgumentException("Error while reading client key manager", e);
            }
        }
        if (cmd.hasOption("clientCertificate") && cmd.hasOption("clientKey")) {
            try {
                builder.clientCertificate(readCertificate(cmd.getOptionValue("clientCertificate")));
                builder.clientCertificateKey(readKey(cmd.getOptionValue("clientKey")));
            }
            catch (Exception e) {
                throw new IllegalArgumentException("Error while reading client certificate or key: " + e.getMessage());
            }
        }
        else if (cmd.hasOption("clientCertificate") || cmd.hasOption("clientKey")) {
            throw new IllegalArgumentException("Options --clientCertificate and --clientKey should always be used together");
        }
    }

    private void processQuantumReadinessTestArg(CommandLine cmd, QuicClientConnection.Builder builder) {
        if (cmd.hasOption("quantumReadinessTest")) {
            try {
                builder.quantumReadinessTest(Integer.parseInt(cmd.getOptionValue("quantumReadinessTest")));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid value for --quantumReadinessTest: " + cmd.getOptionValue("quantumReadinessTest"));
            }
        }
    }

    private void processInitialRttArg(CommandLine cmd, QuicClientConnection.Builder builder) {
        if (cmd.hasOption("initialRtt")) {
            try {
                builder.initialRtt(Integer.parseInt(cmd.getOptionValue("initialRtt")));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid value for --initialRtt: " + cmd.getOptionValue("initialRtt"));
            }
        }
    }

    private void processBufferSizeArg(CommandLine cmd, QuicClientConnection.Builder connectionBuilder) {
        if (cmd.hasOption("B")) {
            String sizeSpecification = cmd.getOptionValue("B");
            Matcher matcher = Pattern.compile("(\\d+)([KM])?").matcher(sizeSpecification);
            if (matcher.matches()) {
                int value = Integer.parseInt(matcher.group(1));
                int unit = 1;
                if (matcher.group(2) != null) {
                    if (matcher.group(2).equals("K")) {
                        unit = 1024;
                    }
                    else if (matcher.group(2).equals("M")) {
                        unit = 1024 * 1024;
                    }
                }
                long bufferSize = value * unit;
                if (bufferSize < MIN_RECEIVER_BUFFER_SIZE || bufferSize > 100 * 1024 * 1024) {
                    throw new IllegalArgumentException(String.format("Buffer size must be between %d and 100M.", MIN_RECEIVER_BUFFER_SIZE));
                }
                else {
                    connectionBuilder.defaultStreamReceiveBufferSize(bufferSize);
                    System.out.println("Receive buffer size set to " + bufferSize + " bytes.");
                }
            }
            else {
                throw new IllegalArgumentException("Invalid buffer size specification: " + sizeSpecification);
            }
        }
    }

    private void executeRequest(String httpRequestPath, String outputFile, QuicClientConnection.Builder builder) throws IOException {

        if (httpVersion == HttpVersion.HTTP3) {
            builder.applicationProtocol("h3");
        }
        else {
            builder.applicationProtocol("hq-interop");
        }
        QuicClientConnection quicConnection = builder.build();

        if (httpRequestPath != null) {
            try {
                HttpClient httpClient = createHttpClient(httpVersion, quicConnection, useZeroRtt);
                InetSocketAddress serverAddress = quicConnection.getServerAddress();
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(new URI("https", null, serverAddress.getHostName(), serverAddress.getPort(), httpRequestPath, null, null))
                        .build();

                Instant start, done;
                long size;
                String response;
                if (outputFile != null) {
                    if (new File(outputFile).isDirectory()) {
                        outputFile = new File(outputFile, new File(httpRequestPath).getName()).getAbsolutePath();
                    }
                    start = Instant.now();
                    HttpResponse<Path> httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofFile(Paths.get(outputFile)));
                    response = httpResponse.toString();
                    done = Instant.now();
                    size = Files.size(httpResponse.body());
                }
                else {
                    start = Instant.now();
                    HttpResponse<String> httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    done = Instant.now();
                    size = httpResponse.body().length();
                    // Wait a little to let logger catch up, so output is printed nicely after all the handshake logging....
                    try {
                        Thread.sleep(500);
                    }
                    catch (InterruptedException e) {}

                    System.out.println("Server returns: \n" +
                            "Status code: " + httpResponse.statusCode() + "\n" +
                            "Headers: \n" +
                            httpResponse.headers().map() + "\n" +
                            "Body (" + size + " bytes): " + printIfPrintable(httpResponse.body()));
                }
                Duration duration = Duration.between(start, done);
                String speed = String.format("%.2f", ((float) size) / duration.toMillis() / 1000);
                System.out.println(String.format("Get requested finished in %.2f sec (%s MB/s).", ((float) duration.toMillis())/1000, speed));
            }
            catch (InterruptedException interruptedException) {
                System.out.println("HTTP request is interrupted");
            }
            catch (URISyntaxException e) {
                // Impossible
                throw new RuntimeException();
            }
        }
        else {
            quicConnection.connect();

            if (keepAliveTime > 0) {
                quicConnection.keepAlive(keepAliveTime);
                try {
                    Thread.sleep((keepAliveTime + 30) * 1000L);
                } catch (InterruptedException e) {}
            }
        }

        if (serverCertificatesFile != null) {
            storeServerCertificates(quicConnection, serverCertificatesFile);
        }

        if (newSessionTicketsFilename != null) {
            storeNewSessionTickets(quicConnection, newSessionTicketsFilename);
        }
        quicConnection.close();
    }

    private String printIfPrintable(String body) {
        boolean notPrintable = body.chars().limit(64).anyMatch(c -> (c < 32 || c > 126) && c != 10 && c != 13 && c != 9);
        if (notPrintable) {
            return "[binary data]";
        }
        else {
            if (body.length() > 64) {
                return body.substring(0, 64) + "\n...[truncated, total " + body.length() + " bytes]...";
            }
            else {
                return body;
            }
        }

    }

    private static boolean loadHttp3ClientClass() {
        try {
            getHttp3ClientClass();
            return true;
        }
        catch (ClassNotFoundException e) {
            return false;
        }
    }

    static HttpClient createHttpClient(HttpVersion httpVersion, QuicClientConnection quicConnection, boolean useZeroRtt) {
        if (httpVersion == HttpVersion.HTTP3) {
            try {
                Class http3ClientClass = getHttp3ClientClass();
                Constructor constructor = http3ClientClass.getConstructor(QuicConnection.class, Duration.class, Long.class);
                // Connection timeout and receive buffer size are not used when client is using an existing quic connection

                long maxReceiveBufferSize = 50_000_000L;
                Duration connectionTimeout = Duration.ofSeconds(60);
                HttpClient http3Client = (HttpClient) constructor.newInstance(quicConnection, connectionTimeout, maxReceiveBufferSize);
                return http3Client;
            }
            catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
                throw new RuntimeException(e);
            }
        }
        else {
            return new Http09Client(quicConnection, useZeroRtt);
        }
    }

    private static Class getHttp3ClientClass() throws ClassNotFoundException {
        Class http3ClientClass;
        try {
            http3ClientClass = KwikCli.class.getClassLoader().loadClass("net.luminis.http3.Http3SingleConnectionClient");
        }
        catch (ClassNotFoundException e) {
            http3ClientClass = KwikCli.class.getClassLoader().loadClass("tech.kwik.flupke.Http3SingleConnectionClient");
        }
        return http3ClientClass;
    }

    private static PrivateKey readKey(String clientKey) throws IOException, InvalidKeySpecException {
        String key = new String(Files.readAllBytes(Paths.get(clientKey)), Charset.defaultCharset());

        if (key.contains("BEGIN PRIVATE KEY")) {
            return loadRSAKey(key);
        }
        else if (key.contains("BEGIN EC PRIVATE KEY")) {
            throw new IllegalArgumentException("EC private key must be in DER format");
        }
        else {
            // Assume DER format
            return loadECKey(Files.readAllBytes(Paths.get(clientKey)));
        }
    }

    private static PrivateKey loadRSAKey(String key) throws InvalidKeySpecException {
        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.getMimeDecoder().decode(privateKeyPEM);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing key algorithm RSA");
        }
    }

    private static PrivateKey loadECKey(byte[] pkcs8key) throws InvalidKeySpecException {
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8key);
            KeyFactory factory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = factory.generatePrivate(spec);
            return privateKey;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing ECDSA support");
        }
    }

    private static X509Certificate readCertificate(String certificateFile) throws IOException, CertificateException {
        String fileContent = new String(Files.readAllBytes(Paths.get(certificateFile)), Charset.defaultCharset());

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        if (fileContent.startsWith("-----BEGIN CERTIFICATE-----")) {
                String encodedCertificate = fileContent
                        .replace("-----BEGIN CERTIFICATE-----", "")
                        .replaceAll(System.lineSeparator(), "")
                        .replace("-----END CERTIFICATE-----", "");
            Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate)));
            return (X509Certificate) certificate;
        }
        else {
            throw new IllegalArgumentException("Invalid certificate file");
        }
    }

    private static void storeServerCertificates(QuicClientConnection quicConnection, String serverCertificatesFile) throws IOException {
        List<X509Certificate> serverCertificateChain = quicConnection.getServerCertificateChain();
        if (! serverCertificatesFile.endsWith(".pem")) {
            serverCertificatesFile += ".pem";
        }
        PrintStream out = new PrintStream(new FileOutputStream(new File(serverCertificatesFile)));
        for (X509Certificate cert: serverCertificateChain) {
            out.println("-----BEGIN CERTIFICATE-----");
            try {
                out.print(new String(Base64.getMimeEncoder().encode(cert.getEncoded())));
            } catch (CertificateEncodingException e) {
                throw new IOException(e.getMessage());
            }
            out.println("\n-----END CERTIFICATE-----");
            out.println("\n");
        }
        out.close();
    }

    private static void storeNewSessionTickets(QuicClientConnection quicConnection, String baseFilename) {
        if (quicConnection.getNewSessionTickets().isEmpty()) {
            // Wait a little, receiver thread might still be busy processing messages.
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
            }

            if (quicConnection.getNewSessionTickets().isEmpty()) {
                System.out.println("There are no new session tickets to store.");
            }
        }

        quicConnection.getNewSessionTickets().stream().forEach(ticket -> storeNewSessionTicket(ticket, baseFilename));
    }

    private static void storeNewSessionTicket(QuicSessionTicket ticket, String baseFilename) {
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

    public static void usage() {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.setWidth(79);
        helpFormatter.printHelp("kwik <host>:<port> OR kwik <host> <port> \tOR kwik http[s]://host:port[/path]", cmdLineOptions);
    }

    public static void main(String[] args) throws Exception {
        try {
            createCommandLineOptions();
            new KwikCli().run(args);
        }
        catch (IllegalArgumentException wrongArgs) {
            System.out.println("Incorrect command: " + wrongArgs.getMessage());
            usage();
        }
    }

    private static void createCommandLineOptions() {
        cmdLineOptions = new Options();
        cmdLineOptions.addOption("l", "log", true, "logging options: [pdrcsiRSD]: " +
                "(p)ackets received/sent, (d)ecrypted bytes, (r)ecovery, (c)ongestion control, (s)tats, (i)nfo, (w)arning, (R)aw bytes, (S)ecrets, (D)ebug; "
                + " default is \"" + DEFAULT_LOG_ARGS + "\", use (n)one to disable");
        cmdLineOptions.addOption("h", "help", false, "show help");
        cmdLineOptions.addOption("v1", "use Quic version 1");
        cmdLineOptions.addOption("v2", "use Quic version 2");
        cmdLineOptions.addOption("v1v2", "use Quic version 1, request version 2");
        cmdLineOptions.addOption("A", "alpn", true, "set alpn (interactive mode only)");
        cmdLineOptions.addOption("R", "resumption key", true, "session ticket file");
        cmdLineOptions.addOption("c", "connectionTimeout", true, "connection timeout in seconds");
        cmdLineOptions.addOption("i", "interactive", false, "start interactive shell");
        cmdLineOptions.addOption("k", "keepAlive", true, "connection keep alive time in seconds");
        cmdLineOptions.addOption("L", "logFile", true, "file to write log message to");
        cmdLineOptions.addOption("O", "output", true, "write server response to file");
        cmdLineOptions.addOption("H", "http", true, "send HTTP GET request, arg is path, e.g. '/index.html'");
        cmdLineOptions.addOption("S", "storeTickets", true, "basename of file to store new session tickets");
        cmdLineOptions.addOption("T", "relativeTime", false, "log with time (in seconds) since first packet");
        cmdLineOptions.addOption("Z", "use0RTT", false, "use 0-RTT if possible (requires -H)");
        cmdLineOptions.addOption(null, "secrets", true, "write secrets to file (Wireshark format)");
        cmdLineOptions.addOption("v", "version", false, "show Kwik version");
        cmdLineOptions.addOption(null, "initialRtt", true, "custom initial RTT value (default is 500)");
        cmdLineOptions.addOption(null, "chacha20", false, "use ChaCha20 as only cipher suite");
        cmdLineOptions.addOption(null, "noCertificateCheck", false, "do not check server certificate");
        cmdLineOptions.addOption(null, "saveServerCertificates", true, "store server certificates in given file");
        cmdLineOptions.addOption(null, "quantumReadinessTest", true, "add number of random bytes to client hello");
        cmdLineOptions.addOption(null, "clientCertificate", true, "certificate (file) for client authentication");
        cmdLineOptions.addOption(null, "clientKey", true, "private key (file) for client certificate");
        cmdLineOptions.addOption(null, "chacha20", false, "use ChaCha20 cipher suite");
        cmdLineOptions.addOption(null, "aes128gcm", false, "use AEAD_AES_128_GCM cipher suite");
        cmdLineOptions.addOption(null, "aes256gcm", false, "use AEAD_AES_256_GCM cipher suite");
        cmdLineOptions.addOption(null, "trustStore", true, "use custom trust store (to use non default CA's)");
        cmdLineOptions.addOption(null, "trustStorePassword", true, "password for custom trust store");
        cmdLineOptions.addOption(null, "keyManager", true, "client authentication key manager");
        cmdLineOptions.addOption(null, "keyManagerPassword", true, "password for client authentication key manager and key password");
        cmdLineOptions.addOption(null, "preferIPv6", false, "use IPv6 address if available");
        cmdLineOptions.addOption("B", "receiveBuffer", true, String.format("receive buffer size, e.g. \"500K\" or \"5M\" (default is %dK)", DEFAULT_MAX_STREAM_DATA / 1024));
    }
}
