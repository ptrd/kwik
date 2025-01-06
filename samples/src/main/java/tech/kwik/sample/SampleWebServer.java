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
package tech.kwik.sample;

import tech.kwik.core.KwikVersion;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.log.FileLogger;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.SysOutLogger;
import tech.kwik.core.server.ApplicationProtocolConnectionFactory;
import tech.kwik.core.server.ServerConnectionConfig;
import tech.kwik.core.server.ServerConnector;

import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Simple sample HTTP3 Web server.
 * For the HTTP/3 implementation, this server uses the Flupke plugin (or add-on) which is not part of the Kwik project.
 * Because Kwik cannot depend compile time on Flupke, the Flupke plugin is loaded dynamically using reflection.
 * If the Flupke plugin is not found, the server will exit.
 *
 * Do not interpret this as a recommended way to implement an HTTP/3 server.
 * The reason for this sample is to have an easy way to test and debug the Kwik server implementation, without the need to
 * make the round-trip to the Flupke project for every change.
 * See the Flupke project for a better implementation of an HTTP/3 server that does not depend on reflection.
 */
public class SampleWebServer {

    private static void usageAndExit() {
        System.err.println("Usage: [--noRetry] cert file, cert key file, port number, www dir");
        System.err.println("   or: [--noRetry] key store file, key store (and key) password, port number, www dir");
        System.exit(1);
    }

    public static void main(String[] rawArgs) throws Exception {
        List<String> args = new ArrayList<>(Arrays.asList(rawArgs));
        if (args.size() < 4) {
            usageAndExit();
        }

        boolean withRetry = true;
        if (args.get(0).equals("--noRetry")) {
            withRetry = false;
            System.out.println("Retry disabled");
            args.remove(0);
        }

        if (args.size() < 4 || args.stream().anyMatch(arg -> arg.startsWith("-"))) {
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

        File certificateFile = null;
        File certificateKeyFile = null;
        KeyStore keyStore = null;
        String keyStorePassword = null;

        if (new File(args.get(0)).exists() && new File(args.get(1)).exists()) {
            certificateFile = new File(args.get(0));
            certificateKeyFile = new File(args.get(1));
        }
        else if (new File(args.get(0)).exists()) {
            File keyStoreFile = new File(args.get(0));
            keyStorePassword = args.get(1);
            keyStore = KeyStore.getInstance(keyStoreFile, keyStorePassword.toCharArray());
        }
        else {
            if (new File(args.get(1)).exists()) {
                System.err.println("Certificate / Keystore file does not exist or is not readable.");
            }
            else {
                System.err.println("Key file does not exist or is not readable.");
            }
            System.exit(1);
        }

        int port = Integer.parseInt(args.get(2));

        File wwwDir = new File(args.get(3));
        if (!wwwDir.exists() || !wwwDir.isDirectory() || !wwwDir.canRead()) {
            System.err.println("Cannot read www dir '" + wwwDir + "'");
            System.exit(1);
        }

        List<QuicConnection.QuicVersion> supportedVersions = new ArrayList<>();
        supportedVersions.add(QuicConnection.QuicVersion.V1);
        supportedVersions.add(QuicConnection.QuicVersion.V2);

        ServerConnectionConfig serverConnectionConfig = ServerConnectionConfig.builder()
                .maxIdleTimeoutInSeconds(30)
                .maxUnidirectionalStreamBufferSize(1_000_000)
                .maxBidirectionalStreamBufferSize(1_000_000)
                .maxConnectionBufferSize(10_000_000)
                .maxOpenPeerInitiatedUnidirectionalStreams(10)
                .maxOpenPeerInitiatedBidirectionalStreams(100)
                .retryRequired(withRetry)
                .connectionIdLength(8)
                .build();

        ServerConnector.Builder builder = ServerConnector.builder()
                .withPort(port)
                .withSupportedVersions(supportedVersions)
                .withConfiguration(serverConnectionConfig)
                .withLogger(log);

        if (certificateFile != null) {
            builder.withCertificate(new FileInputStream(certificateFile), new FileInputStream(certificateKeyFile));
        }
        else {
            String alias = keyStore.aliases().nextElement();
            System.out.println("Using certificate with alias " + alias + " from keystore");
            builder.withKeyStore(keyStore, alias, keyStorePassword.toCharArray());
        }

        ServerConnector serverConnector = builder.build();

        registerHttp3(serverConnector, wwwDir, supportedVersions, log);

        serverConnector.start();
        log.info("Kwik server " + KwikVersion.getVersion() + " started; supported application protocols: "
                + serverConnector.getRegisteredApplicationProtocols());
    }

    private static void registerHttp3(ServerConnector serverConnector, File wwwDir, List<QuicConnection.QuicVersion> supportedVersions, Logger log) {
        ApplicationProtocolConnectionFactory http3ApplicationProtocolConnectionFactory = null;

        try {
            // If flupke server plugin is on classpath, load the http3 connection factory class.
            Class<?> http3FactoryClass = SampleWebServer.class.getClassLoader().loadClass("net.luminis.http3.server.Http3ApplicationProtocolFactory");
            http3ApplicationProtocolConnectionFactory = (ApplicationProtocolConnectionFactory)
                    http3FactoryClass.getDeclaredConstructor(new Class[]{ File.class }).newInstance(wwwDir);
            log.info("Loading Flupke H3 server plugin");

            serverConnector.registerApplicationProtocol("h3", http3ApplicationProtocolConnectionFactory);
        }
        catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            log.error("No H3 protocol: Flupke plugin not found.");
            System.exit(1);
        }
    }
}
