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
package tech.kwik.interop;

import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicSessionTicket;
import tech.kwik.core.QuicStream;
import tech.kwik.h09.client.Http09Client;
import tech.kwik.core.impl.QuicClientConnectionImpl;
import tech.kwik.core.log.FileLogger;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.NullLogger;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;


public class InteropClient {

    public static final String TC_TRANSFER = "transfer";
    public static final String TC_RESUMPTION = "resumption";
    public static final String TC_MULTI = "multiconnect";
    public static final String TC_0RTT = "zerortt";
    public static final String TC_KEYUPDATE = "keyupdate";
    public static List TESTCASES = List.of(TC_TRANSFER, TC_RESUMPTION, TC_MULTI, TC_0RTT, TC_KEYUPDATE);

    private static File outputDir;
    private static Logger logger;
    private static KeyStore trustStore;


    public static void main(String[] args) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        File logDir = new File("/logs");   // Interop runner runs in docker container and is expected to write logs to /logs
        String logFile = (logDir.exists()? "/logs/": "./") + "kwik_client.log";
        try {
            logger = new FileLogger(new File(logFile));
            logger.logInfo(true);
            logger.logWarning(true);
        } catch (IOException e) {
            System.out.println("Cannot open log file " + logFile);
            System.exit(1);
        }

        if (args.length < 2) {
            System.out.println("Expected 5 arguments: <downloadDir> <trustStore> <trustStorePassword> <testcase> <URL>");
            System.exit(1);
        }

        int currentArg = 0;
        outputDir = new File(args[currentArg++]);
        if (! outputDir.isDirectory()) {
            outputDir.mkdir();
        }

        File trustStoreFile = new File(args[currentArg++]);
        if (! trustStoreFile.exists() || ! trustStoreFile.canRead()) {
            System.out.println("Can't read trust store file " + trustStoreFile);
            System.exit(1);
        }
        String trustStorePassword = args[currentArg++];
        trustStore = KeyStore.getInstance(trustStoreFile, trustStorePassword.toCharArray());

        String testCase = args[currentArg++];
        if (! TESTCASES.contains(testCase)) {
            System.out.println("Invalid argument; test case '" + testCase + "' not known.");
            System.out.println("Available test cases: " + TESTCASES);
        }

        try {
            List<URL> downloadUrls = new ArrayList<>();
            for (; currentArg < args.length; currentArg++) {
                downloadUrls.add(new URL(args[currentArg]));
            }

            QuicClientConnectionImpl.Builder builder = QuicClientConnectionImpl.newBuilder();
            builder.version(QuicConnection.QuicVersion.V1);
            builder.applicationProtocol("hq-interop");
            builder.customTrustStore(trustStore);
            builder.uri(downloadUrls.get(0).toURI());
            builder.logger(logger);
            builder.initialRtt(100);
            builder.connectTimeout(Duration.ofSeconds(30));
            String keylogfileEnvVar = System.getenv("SSLKEYLOGFILE");
            if (keylogfileEnvVar != null && ! keylogfileEnvVar.isBlank()) {
                System.out.println("Writing keys to " + keylogfileEnvVar);
                builder.secrets(Paths.get(keylogfileEnvVar));
            }

            if (testCase.equals(TC_TRANSFER)) {
                testTransfer(downloadUrls, builder);
            }
            else if (testCase.equals(TC_RESUMPTION)) {
                testResumption(downloadUrls, builder);
            }
            else if (testCase.equals(TC_MULTI)) {
                testMultiConnect(downloadUrls, builder);
            }
            else if (testCase.equals(TC_0RTT)) {
                testZeroRtt(downloadUrls, builder);
            }
            else if (testCase.equals(TC_KEYUPDATE)) {
                testKeyUpdate(downloadUrls, builder);
            }
        } catch (MalformedURLException | URISyntaxException e) {
            System.out.println("Invalid argument: cannot parse URL '" + args[currentArg] + "'");
        } catch (IOException e) {
            System.out.println("I/O Error: " + e);
        }
    }

    private static void testTransfer(List<URL> downloadUrls, QuicClientConnectionImpl.Builder builder) throws IOException, URISyntaxException {
        // Disable logger for testcase transfer, because it has significant impact on performance (and "transfer" is used for performance testing).
        builder.logger(new NullLogger());
        QuicClientConnection connection = builder.build();
        connection.connect();

        ForkJoinPool myPool = new ForkJoinPool(Integer.min(100, downloadUrls.size()));
        try {
            myPool.submit(() ->
                    downloadUrls.parallelStream()
                            .forEach(url -> {
                                try {
                                    http09Request(connection, url, outputDir);
                                }
                                catch (IOException e) {
                                    logger.error("downloading " + url + " failed", e);
                                }
                            }))
                    .get(5, TimeUnit.MINUTES);
            logger.info("Downloaded " + downloadUrls);
        } catch (InterruptedException e) {
            logger.error("download tasks interrupted", e);
        } catch (ExecutionException e) {
            logger.error("download tasks failed", e);
        } catch (TimeoutException e) {
            logger.error("download tasks timed out...", e);
        }

        connection.close();
    }

    private static void testResumption(List<URL> downloadUrls, QuicClientConnectionImpl.Builder builder) throws IOException, URISyntaxException {
        if (downloadUrls.size() != 2) {
            throw new IllegalArgumentException("expected 2 download URLs");
        }
        URL url1 = downloadUrls.get(0);
        URL url2 = downloadUrls.get(1);

        QuicClientConnection connection = builder.build();
        connection.connect();

        http09Request(connection, url1, outputDir);
        logger.info("Downloaded " + url1);

        List<QuicSessionTicket> newSessionTickets = connection.getNewSessionTickets();

        connection.close();

        if (newSessionTickets.isEmpty()) {
            logger.info("Server did not provide any new session tickets.");
            System.exit(1);
        }

        builder = QuicClientConnectionImpl.newBuilder();
        builder.version(QuicConnection.QuicVersion.V1);
        builder.applicationProtocol("hq-interop");
        builder.uri(url2.toURI());
        builder.customTrustStore(trustStore);  // Not necessary if server accepts PSK, but when not, test would fail for wrong reason.
        builder.logger(logger);
        builder.sessionTicket(newSessionTickets.get(0));
        QuicClientConnection connection2 = builder.build();
        connection2.connect();
        http09Request(connection2, url2, outputDir);
        logger.info("Downloaded " + url2);
        connection2.close();
    }

    private static void testMultiConnect(List<URL> downloadUrls, QuicClientConnectionImpl.Builder builder) throws URISyntaxException {
        logger.useRelativeTime(true);
        logger.logRecovery(true);
        logger.logCongestionControl(true);
        logger.logPackets(true);

        for (URL download : downloadUrls) {
            QuicClientConnection connection = null;
            try {
                connection = builder.build();
                logger.info("Setting up connection for downloading " + download + " at " + timeNow() + " on " + connection);

                connection.connect();

                logger.info("Starting downloading " + download + " at " + timeNow() + " on " + connection);

                http09Request(connection, download, outputDir);

                logger.info("Finished downloading " + download + " at " + timeNow() + " on " + connection);

                connection.close();
            }
            catch (IOException ioError) {
                logger.error(timeNow() + " Error in client: " + ioError + " for " + connection);
            }
        }
    }

    private static void testZeroRtt(List<URL> downloadUrls, QuicClientConnectionImpl.Builder builder) throws IOException {
        logger.logPackets(true);
        logger.logRecovery(true);
        logger.info("Starting first download at " + timeNow());

        builder.connectTimeout(Duration.ofSeconds(15));
        QuicClientConnection connection = builder.build();
        connection.connect();

        http09Request(connection, downloadUrls.get(0), outputDir);
        logger.info("Downloaded " + downloadUrls.get(0) + " finished at " + timeNow());
        List<QuicSessionTicket> newSessionTickets = connection.getNewSessionTickets();
        if (newSessionTickets.isEmpty()) {
            logger.error("Error: did not get any new session tickets; aborting test.");
            return;
        }
        else {
            logger.info("Got " + newSessionTickets.size() + " new session tickets");
        }
        connection.close();
        logger.info("Connection closed; starting second connection with 0-rtt");

        builder.sessionTicket(newSessionTickets.get(0));
        builder.connectTimeout(Duration.ofSeconds(15));
        QuicClientConnection connection2 = builder.build();

        List<QuicClientConnection.StreamEarlyData> earlyDataRequests = new ArrayList<>();
        for (int i = 1; i < downloadUrls.size(); i++) {
            String httpRequest = "GET " + downloadUrls.get(i).getPath() + "\r\n";
            earlyDataRequests.add(new QuicClientConnection.StreamEarlyData(httpRequest.getBytes(), true));
        }

        String alpn = "hq-interop";
        List<QuicStream> earlyDataStreams = connection2.connect(earlyDataRequests);
        for (int i = 0; i < earlyDataRequests.size(); i++) {
            if (earlyDataStreams.get(i) == null) {
                logger.info("Attempting to create new stream after connect, because it failed on 0-rtt");
            }
            else {
                logger.info("Processing response for stream " + earlyDataStreams.get(i));
            }
            http09RequestWithZeroRttStream(connection, downloadUrls.get(i+1).getPath(), earlyDataStreams.get(i), outputDir.getAbsolutePath());
        }

        logger.info("Download finished at " + timeNow());
        connection.close();
    }

    private static void testKeyUpdate(List<URL> downloadUrls, QuicClientConnectionImpl.Builder builder) throws IOException {
        logger.logPackets(true);
        logger.info("Starting download at " + timeNow());

        QuicClientConnection connection = builder.build();
        connection.connect();

        String requestPath = downloadUrls.get(0).getPath();
        String outputFile = outputDir.getAbsolutePath();

        QuicStream httpStream = connection.createStream(true);
        httpStream.getOutputStream().write(("GET " + requestPath + "\r\n").getBytes());
        httpStream.getOutputStream().close();

        String fileName = requestPath;
        FileOutputStream  out = new FileOutputStream(new File(outputFile, fileName));
        // Read the first 100KB of bytes (approx.)
        transfer(httpStream.getInputStream(), out, 100 * 1024);
        // Initiate the key update; test specification requires the update to take place before 1MB is downloaded.
        logger.info("Initiating key update");
        ((QuicClientConnectionImpl) connection).updateKeys();
        // And download the rest.
        httpStream.getInputStream().transferTo(out);
        logger.info("Downloaded " + downloadUrls.get(0) + " finished at " + timeNow());
    }

    private static void http09Request(QuicClientConnection connection, URL url, File outputDir) throws IOException {
        try {
            HttpClient httpClient = new Http09Client(connection, false);
            HttpRequest request = HttpRequest.newBuilder().uri(url.toURI()).build();
            String fileName = new File(url.getFile()).getName();
            httpClient.send(request, HttpResponse.BodyHandlers.ofFile(Paths.get(outputDir.getAbsolutePath(), fileName)));
        }
        catch (URISyntaxException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private static void http09RequestWithZeroRttStream(QuicConnection quicConnection, String requestPath, QuicStream httpStream, String outputFile) throws IOException {
        FileOutputStream out;
        if (new File(outputFile).isDirectory()) {
            String fileName = requestPath;
            if (fileName.equals("/")) {
                fileName = "index";
            }
            out = new FileOutputStream(new File(outputFile, fileName));
        }
        else {
            out = new FileOutputStream(outputFile);
        }
        httpStream.getInputStream().transferTo(out);
    }


    private static void transfer(InputStream in, FileOutputStream out, int bytes) throws IOException {
        byte[] buffer = new byte[1200];
        int transferred = 0;
        int read;
        while (transferred < bytes && (read = in.read(buffer, 0, 1200)) >= 0) {
            out.write(buffer, 0, read);
            transferred += read;
        }
    }

    static String timeNow() {
        LocalTime localTimeNow = LocalTime.from(Instant.now().atZone(ZoneId.systemDefault()));
        DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("mm:ss.SSS");
        return timeFormatter.format(localTimeNow);
    }

}

