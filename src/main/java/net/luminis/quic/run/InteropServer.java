/*
 * Copyright © 2022, 2023 Peter Doornbosch
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

import net.luminis.quic.core.Version;
import net.luminis.quic.log.FileLogger;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.SysOutLogger;
import net.luminis.quic.server.ApplicationProtocolConnectionFactory;
import net.luminis.quic.server.ServerConnectionConfig;
import net.luminis.quic.server.ServerConnector;
import net.luminis.quic.server.h09.Http09ApplicationProtocolFactory;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.InvocationTargetException;
import java.util.List;

/**
 * Demo server that provides both QUIC v1, as well as some older IETF draft versions, all with "HTTP 0.9", a.k.a. hq-interop.
 * The "hq-interop" protocol is used in the interoperability tests, see https://interop.seemann.io/.
 * If the flupke-plugin is on the classpath, HTTP3 protocol is also provided with the same QUIC versions.
 */
public class InteropServer {

    private static void usageAndExit() {
        System.err.println("Usage: [--noRetry] cert file, cert key file, port number [www dir]");
        System.exit(1);
    }

    public static void main(String[] rawArgs) throws Exception {
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
        if (logDir.exists() && logDir.isDirectory() && logDir.canWrite()) {
            log = new FileLogger(new File(logDir, "kwikserver.log"));
        }
        else {
            log = new SysOutLogger();
        }
        log.timeFormat(Logger.TimeFormat.Long);
        log.logWarning(true);
        log.logInfo(true);


        File certificateFile = new File(args.get(0));
        if (!certificateFile.exists()) {
            System.err.println("Cannot open certificate file " + args.get(0));
            System.exit(1);
        }

        File certificateKeyFile = new File(args.get(1));
        if (!certificateKeyFile.exists()) {
            System.err.println("Cannot open certificate file " + args.get(1));
            System.exit(1);
        }

        int port = Integer.parseInt(args.get(2));

        File wwwDir = null;
        if (args.size() > 3) {
            wwwDir = new File(args.get(3));
            if (!wwwDir.exists() || !wwwDir.isDirectory() || !wwwDir.canRead()) {
                System.err.println("Cannot read www dir '" + wwwDir + "'");
                System.exit(1);
            }
        }

        List<Version> supportedVersions = List.of(Version.QUIC_version_1);

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
                .withCertificate(new FileInputStream(certificateFile), new FileInputStream(certificateKeyFile))
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
            Class<?> http3FactoryClass = InteropServer.class.getClassLoader().loadClass("net.luminis.http3.server.Http3ApplicationProtocolFactory");
            http3ApplicationProtocolConnectionFactory = (ApplicationProtocolConnectionFactory)
                    http3FactoryClass.getDeclaredConstructor(new Class[]{ File.class }).newInstance(wwwDir);
            log.info("Loading Flupke H3 server plugin");
        } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
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
}
