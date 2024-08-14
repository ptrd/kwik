/*
 * Copyright © 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.server;

import net.luminis.quic.QuicConnection;
import net.luminis.quic.log.Logger;
import net.luminis.quic.server.impl.ServerConnectorImpl;

import java.io.InputStream;
import java.net.DatagramSocket;
import java.security.KeyStore;
import java.util.List;
import java.util.Set;

/**
 * Listens for QUIC connections on a given port. Requires server certificate and corresponding private key.
 */
public interface ServerConnector {

    void registerApplicationProtocol(String protocol, ApplicationProtocolConnectionFactory protocolConnectionFactory);

    Set<String> getRegisteredApplicationProtocols();

    void start();

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

        ServerConnector build() throws Exception;
    }
}
