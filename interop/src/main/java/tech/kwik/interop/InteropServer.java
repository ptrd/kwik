/*
 * Copyright © 2022, 2023, 2024, 2025 Peter Doornbosch
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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import tech.kwik.core.KwikVersion;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.log.FileLogger;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.log.SysOutLogger;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;
import tech.kwik.h09.server.Http09ApplicationProtocolFactory;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.util.List;

/**
 * Server that provides QUIC v1 and v2, with "HTTP 0.9", a.k.a. hq-interop, used for interoperability testing.
 * The "hq-interop" protocol is used in the interoperability tests, see https://interop.seemann.io/.
 * If the flupke-plugin is on the classpath, HTTP3 protocol is also provided with the same QUIC versions.
 */
public class InteropServer {

    static boolean suppressLoggingForTransferTest = false;

    private static void usageAndExit() {
        System.err.println("Usage: [--noRetry] keystore-file cert-alias keystore-password, key-password, port-number [www dir]");
        System.exit(1);
    }

    public static void main(String[] rawArgs) throws Exception {
        String testcase = System.getenv("TESTCASE");
        if (testcase == null) {
            testcase = "";
        }

        Options cmdLineOptions = new Options();
        cmdLineOptions.addOption(null, "noRetry", false, "disable always use retry");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = parser.parse(cmdLineOptions, rawArgs);
        }
        catch (ParseException argError) {
            System.out.println("Invalid argument: " + argError.getMessage());
            usageAndExit();
        }

        List<String> args = cmd.getArgList();
        if (args.size() < 3) {
            usageAndExit();
        }

        Logger log;
        File logDir = new File("/logs");
        if (logDir.exists() && logDir.isDirectory() && logDir.canWrite() && (!testcase.equals("transfer") || !suppressLoggingForTransferTest)) {
            log = new FileLogger(new File(logDir, "kwikserver.log"));
        }
        else if (suppressLoggingForTransferTest && testcase.equals("transfer")) {
            // Disable logger for testcase transfer, because it has significant impact on performance (and "transfer" is used for performance testing).
            log = new NullLogger();
        }
        else {
            log = new SysOutLogger();
        }

        log.timeFormat(Logger.TimeFormat.Long);
        log.logWarning(true);
        log.logInfo(true);

        File keyStoreFile = new File(args.get(0));
        if (!keyStoreFile.exists()) {
            System.err.println("Cannot open keystore file " + args.get(0));
            System.exit(1);
        }

        String certificateAlias = args.get(1);
        String keyStorePassword = args.get(2);
        String keyPassword = args.get(3);

        KeyStore keyStore = KeyStore.getInstance(keyStoreFile, keyStorePassword.toCharArray());
        if (keyStore.getCertificateChain(certificateAlias) == null) {
            System.err.println("Certificate alias '" + certificateAlias + "' not found in keystore");
            System.exit(1);
        }

        int port = Integer.parseInt(args.get(4));

        File wwwDir = null;
        if (args.size() > 5) {
            wwwDir = new File(args.get(5));
            if (!wwwDir.exists() || !wwwDir.isDirectory() || !wwwDir.canRead()) {
                System.err.println("Cannot read www dir '" + wwwDir + "'");
                System.exit(1);
            }
        }

        List<QuicConnection.QuicVersion> supportedVersions = List.of(QuicConnection.QuicVersion.V1, QuicConnection.QuicVersion.V2);

        ServerConnectionConfig serverConnectionConfig = ServerConnectionConfig.builder()
                .maxIdleTimeoutInSeconds(30)
                .maxUnidirectionalStreamBufferSize(1_000_000)
                .maxBidirectionalStreamBufferSize(1_000_000)
                .maxConnectionBufferSize(10_000_000)
                .maxOpenPeerInitiatedUnidirectionalStreams(10)
                .maxOpenPeerInitiatedBidirectionalStreams(100)
                .retryRequired(! cmd.hasOption("noRetry"))
                .connectionIdLength(8)
                .build();

        ServerConnector serverConnector = ServerConnector.builder()
                .withPort(port)
                .withKeyStore(keyStore, certificateAlias, keyPassword.toCharArray())
                .withSupportedVersions(supportedVersions)
                .withConfiguration(serverConnectionConfig)
                .withLogger(log)
                .build();

        if (wwwDir != null) {
            registerApplicationLayerProtocols(serverConnector, wwwDir, log);
        }

        serverConnector.start();
        log.info("Kwik server " + KwikVersion.getVersion() + " started; supported application protocols: "
                + serverConnector.getRegisteredApplicationProtocols());
    }

    private static void registerApplicationLayerProtocols(ServerConnector serverConnector, File wwwDir, Logger log) {
        ApplicationProtocolConnectionFactory http3ApplicationProtocolConnectionFactory = null;

        try {
            // If flupke server plugin is on classpath, load the http3 connection factory class.
            http3ApplicationProtocolConnectionFactory = http3FlupkeOld(wwwDir);
            if (http3ApplicationProtocolConnectionFactory == null) {
                http3ApplicationProtocolConnectionFactory = http3FlupkeNew(wwwDir);
            }
            log.info("Loading Flupke H3 server plugin");
        }
        catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            log.info("No Flupke H3 server plugin." + e.getMessage());
        }

        Http09ApplicationProtocolFactory http09ApplicationProtocolFactory = new Http09ApplicationProtocolFactory(wwwDir);

        final ApplicationProtocolConnectionFactory http3ApplicationProtocolFactory = http3ApplicationProtocolConnectionFactory;
        String protocol = "hq-interop";
        serverConnector.registerApplicationProtocol(protocol, http09ApplicationProtocolFactory);

        if (http3ApplicationProtocolFactory != null) {
            String h3Protocol = protocol.replace("hq-interop", "h3");
            serverConnector.registerApplicationProtocol(h3Protocol, http3ApplicationProtocolFactory);
        }
    }

    private static ApplicationProtocolConnectionFactory http3FlupkeOld(File wwwDir) {
        try {
            Class<?> http3FactoryClass = InteropServer.class.getClassLoader().loadClass("net.luminis.http3.server.Http3ApplicationProtocolFactory");
            return (ApplicationProtocolConnectionFactory)
                    http3FactoryClass.getDeclaredConstructor(new Class[]{File.class}).newInstance(wwwDir);
        }
        catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            System.out.println("Old Flupke plugin not found");
            return null;
        }
    }

    private static ApplicationProtocolConnectionFactory http3FlupkeNew(File wwwDir) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        Class<?> http3FactoryClass = InteropServer.class.getClassLoader().loadClass("tech.kwik.flupke.sample.kwik.Http3SimpleFileServerApplicationProtocolConnectionFactory");
        return (ApplicationProtocolConnectionFactory)
                http3FactoryClass.getDeclaredConstructor(new Class[]{ File.class }).newInstance(wwwDir);
    }
}
