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

import net.luminis.quic.QuicSessionTicket;
import net.luminis.quic.QuicConnection;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.Version;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;


public class InteropRunner extends KwikCli {

    public static final String TC_TRANSFER = "transfer";
    public static final String TC_RESUMPTION = "resumption";
    public static List TESTCASES = List.of(TC_TRANSFER, TC_RESUMPTION);

    public static File outputDir;

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

        try {
            List<URL> downloadUrls = new ArrayList<>();
            for (int i = 2; i < args.length; i++) {
                downloadUrls.add(new URL(args[i]));
            }

            if (testCase.equals("transfer")) {
                testTransfer(downloadUrls);
            }
            if (testCase.equals("resumption")) {
                testResumption(downloadUrls);
            }
        } catch (MalformedURLException e) {
            System.out.println("Invalid (second) argument: cannot parse URL '" + args[1] + "'");
        } catch (IOException e) {
            System.out.println("I/O Error: " + e);
        }
    }

    private static void testTransfer(List<URL> downloadUrls) throws IOException {
        URL url1 = downloadUrls.get(0);
        SysOutLogger logger = new SysOutLogger();
        // logger.logPackets(true);

        QuicConnection connection = new QuicConnection(url1.getHost(), url1.getPort(), logger);
        connection.connect(5_000);

        ForkJoinPool myPool = new ForkJoinPool(downloadUrls.size());
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

    private static void testResumption(List<URL> downloadUrls) throws IOException {
        if (downloadUrls.size() != 2) {
            throw new IllegalArgumentException("expected 2 download URLs");
        }
        URL url1 = downloadUrls.get(0);
        URL url2 = downloadUrls.get(1);
        SysOutLogger logger = new SysOutLogger();
        // logger.logPackets(true);

        QuicConnection connection = new QuicConnection(url1.getHost(), url1.getPort(), logger);
        connection.connect(5_000);

        doHttp09Request(connection, url1.getPath(), outputDir.getAbsolutePath());
        System.out.println("Downloaded " + url1);

        List<QuicSessionTicket> newSessionTickets = connection.getNewSessionTickets();

        connection.close();

        if (newSessionTickets.isEmpty()) {
            System.out.println("Server did not provide any new session tickets.");
            System.exit(1);
        }

        QuicSessionTicket sessionTicket = QuicSessionTicket.deserialize(newSessionTickets.get(0).serialize());   // TODO: oops!

        QuicConnection connection2 = new QuicConnection(url2.getHost(), url2.getPort(), sessionTicket, Version.getDefault(), logger);
        connection2.connect(5_000);
        doHttp09Request(connection2, url2.getPath(), outputDir.getAbsolutePath());
        System.out.println("Downloaded " + url2);
        connection2.close();
    }


}

