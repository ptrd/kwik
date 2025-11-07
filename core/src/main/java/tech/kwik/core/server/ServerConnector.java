/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.server;

import tech.kwik.core.QuicConnection;
import tech.kwik.core.log.Logger;
import tech.kwik.core.server.impl.ServerConnectorImpl;

import java.io.InputStream;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Set;

/**
 * Listens for QUIC connections on a given port. Requires server certificate and corresponding private key.
 */
public interface ServerConnector extends AutoCloseable {

    /**
     * Register the provided protocol connection factory with this connector, using the provided protocol.
     * @param protocol
     * @param protocolConnectionFactory
     */
    void registerApplicationProtocol(String protocol, ApplicationProtocolConnectionFactory protocolConnectionFactory);

    /**
     * Returns a set of registered protocol ALPNs.
     */
    Set<String> getRegisteredApplicationProtocols();

    void start();

    /**
     * Closes the server connector and releases all resources. This includes refusing new connections and
     * properly closing all existing connections. This method returns after all connections are closed or after
     * a fixed timeout.
     */
    void close();

    static Builder builder() {
        return new ServerConnectorImpl.BuilderImpl();
    }

    interface Builder {

        Builder withPort(int port);

        Builder withSocket(DatagramSocket socket);

        @Deprecated
        Builder withCertificate(InputStream certificateFile, InputStream certificateKeyFile);

        Builder withKeyStore(KeyStore keyStore, String certificateAlias, char[] privateKeyPassword);

        /**
         * Adds the given key store to the server connector. The key store should contain the server certificate or
         * certificate chain and the corresponding private key. The key must be protected by the given password.
         * The name of the EC-curve can be specified for cases where it cannot be automatically determined from the
         * server certificate.
         * @param keyStore
         * @param certificateAlias
         * @param privateKeyPassword
         * @param ecCurve  The name of the EC-curve used by the public key in the certificate. If null, the curve is
         *                 determined from the certificate (if possible). Valid values are "secp256r1", "secp384r1" and "secp521r1".
         * @return
         */
        Builder withKeyStore(KeyStore keyStore, String certificateAlias, char[] privateKeyPassword, String ecCurve);

        Builder withSupportedVersions(List<QuicConnection.QuicVersion> supportedVersions);

        Builder withSupportedVersion(QuicConnection.QuicVersion supportedVersion);

        Builder withConfiguration(ServerConnectionConfig configuration);

        Builder withLogger(Logger log);

        /**
         * Builds the server connector.
         * @return
         * @throws SocketException       if the connector could not create a DatagramSocket or could not bind it to the given port
         * @throws CertificateException  if the certificate's signature algorithm is not supported, or the EC-curve cannot be determined.
         * In the latter case, use the
         * {@link #withKeyStore(KeyStore keyStore, String certificateAlias, char[] privateKeyPassword, String ecCurve)}
         * method to explicitly specify the EC-curve.
         */
        ServerConnector build() throws SocketException, CertificateException;
    }
}
