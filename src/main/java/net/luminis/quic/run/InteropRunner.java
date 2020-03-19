/*
 * Copyright © 2019, 2020 Peter Doornbosch
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
import net.luminis.quic.QuicConnectionImpl;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.tls.NewSessionTicket;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
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


public class InteropRunner extends KwikCli {

    public static final String TC_TRANSFER = "transfer";
    public static final String TC_RESUMPTION = "resumption";
    public static final String TC_MULTI = "multiconnect";
    public static List TESTCASES = List.of(TC_TRANSFER, TC_RESUMPTION, TC_MULTI);

    private static File outputDir;
    private static SysOutLogger logger = new SysOutLogger();


    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Expected at least 3 arguments: <downloadDir> <testcase> <URL>");
            System.exit(1);
        }

        outputDir = new File(args[0]);
        if (! outputDir.isDirectory()) {
            outputDir.mkdir();
        }

        String testCase = args[1];
        if (! TESTCASES.contains(testCase)) {
            System.out.println("Invalid argument; test case '" + testCase + "' not known.");
            System.out.println("Available test cases: " + TESTCASES);
        }

        int i = -1;
        try {
            List<URL> downloadUrls = new ArrayList<>();
            for (i = 2; i < args.length; i++) {
                downloadUrls.add(new URL(args[i]));
            }

            QuicConnectionImpl.Builder builder = QuicConnectionImpl.newBuilder();
            builder.uri(downloadUrls.get(0).toURI());
            builder.logger(logger);
            builder.initialRtt(100);

            if (testCase.equals(TC_TRANSFER)) {
                testTransfer(downloadUrls, builder);
            }
            else if (testCase.equals(TC_RESUMPTION)) {
                testResumption(downloadUrls, builder);
            }
            else if (testCase.equals(TC_MULTI)) {
                testMultiConnect(downloadUrls, builder);
            }
        } catch (MalformedURLException | URISyntaxException e) {
            System.out.println("Invalid argument: cannot parse URL '" + args[i] + "'");
        } catch (IOException e) {
            System.out.println("I/O Error: " + e);
        }
    }

    private static void testTransfer(List<URL> downloadUrls, QuicConnectionImpl.Builder builder) throws IOException, URISyntaxException {
        URL url1 = downloadUrls.get(0);
        // logger.logPackets(true);
        logger.logInfo(true);
        logger.logCongestionControl(true);
        logger.logRecovery(true);

        QuicConnection connection = builder.build();
        connection.connect(5_000);

        ForkJoinPool myPool = new ForkJoinPool(Integer.min(100, downloadUrls.size()));
        try {
            myPool.submit(() ->
                    downloadUrls.parallelStream()
                            .forEach(url -> {
                                try {
                                    doHttp09Request(connection, url.getPath(), outputDir.getAbsolutePath());
                                } catch (IOException e) {
                                    throw new RuntimeException(e);
                                }
                            }))
                    .get(5, TimeUnit.MINUTES);
            System.out.println("Downloaded " + downloadUrls);
        } catch (InterruptedException e) {
            logger.error("download tasks interrupted", e);
        } catch (ExecutionException e) {
            logger.error("download tasks failed", e);
        } catch (TimeoutException e) {
            logger.error("download tasks timed out...", e);
        }

        connection.close();
    }

    private static void testResumption(List<URL> downloadUrls, QuicConnectionImpl.Builder builder) throws IOException, URISyntaxException {
        if (downloadUrls.size() != 2) {
            throw new IllegalArgumentException("expected 2 download URLs");
        }
        URL url1 = downloadUrls.get(0);
        URL url2 = downloadUrls.get(1);
        // logger.logPackets(true);

        QuicConnection connection = builder.build();
        connection.connect(5_000);

        doHttp09Request(connection, url1.getPath(), outputDir.getAbsolutePath());
        System.out.println("Downloaded " + url1);

        List<NewSessionTicket> newSessionTickets = connection.getNewSessionTickets();

        connection.close();

        if (newSessionTickets.isEmpty()) {
            System.out.println("Server did not provide any new session tickets.");
            System.exit(1);
        }

        NewSessionTicket sessionTicket = NewSessionTicket.deserialize(newSessionTickets.get(0).serialize());   // TODO: oops!

        builder = QuicConnectionImpl.newBuilder();
        builder.uri(url2.toURI());
        builder.logger(logger);
        builder.sessionTicket(sessionTicket);
        QuicConnection connection2 = builder.build();
        connection2.connect(5_000);
        doHttp09Request(connection2, url2.getPath(), outputDir.getAbsolutePath());
        System.out.println("Downloaded " + url2);
        connection2.close();
    }

    private static void testMultiConnect(List<URL> downloadUrls, QuicConnectionImpl.Builder builder) throws URISyntaxException {
        logger.useRelativeTime(true);
        logger.logRecovery(true);
        // logger.logCongestionControl(true);
        logger.logInfo(true);
        logger.logPackets(true);

        for (URL download : downloadUrls) {
            try {
                System.out.println("Starting download at " + timeNow());

                QuicConnection connection = builder.build();
                connection.connect(15_000);

                doHttp09Request(connection, download.getPath(), outputDir.getAbsolutePath());
                System.out.println("Downloaded " + download + " finished at " + timeNow());

                connection.close();
            }
            catch (IOException ioError) {
                System.out.println(timeNow() + " Error in client: " + ioError);
            }
        }
    }

    static String timeNow() {
        LocalTime localTimeNow = LocalTime.from(Instant.now().atZone(ZoneId.systemDefault()));
        DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("mm:ss.SSS");
        return timeFormatter.format(localTimeNow);
    }

}

