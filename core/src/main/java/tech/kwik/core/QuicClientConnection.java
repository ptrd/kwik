/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.core;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.core.impl.QuicClientConnectionImpl;
import tech.kwik.core.log.Logger;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;


public interface QuicClientConnection extends QuicConnection {

    void connect() throws IOException;

    List<QuicStream> connect(List<StreamEarlyData> earlyData) throws IOException;

    void keepAlive(int seconds);

    List<QuicSessionTicket> getNewSessionTickets();

    InetSocketAddress getLocalAddress();

    InetSocketAddress getServerAddress();

    List<X509Certificate> getServerCertificateChain();

    boolean isConnected();

    static Builder newBuilder() {
        return QuicClientConnectionImpl.newBuilder();
    }

    class StreamEarlyData {
        byte[] data;
        boolean closeOutput;

        public StreamEarlyData(byte[] data, boolean closeImmediately) {
            this.data = data;
            closeOutput = closeImmediately;
        }

        public byte[] getData() {
            return data;
        }

        public boolean isCloseOutput() {
            return closeOutput;
        }
    }

    interface Builder {

        QuicClientConnection build() throws SocketException, UnknownHostException;

        Builder applicationProtocol(String applicationProtocol);

        Builder connectTimeout(Duration duration);

        Builder maxIdleTimeout(Duration duration);

        Builder defaultStreamReceiveBufferSize(Long bufferSize);

        /**
         * The maximum number of peer initiated bidirectional streams that the peer is allowed to have open at any time.
         * If the value is 0, the peer is not allowed to open any bidirectional stream.
         * @param max
         * @return
         */
        Builder maxOpenPeerInitiatedBidirectionalStreams(int max);

        /**
         * The maximum number of peer initiated unidirectional streams that the peer is allowed to have open at any time.
         * If the value is 0, the peer is not allowed to open any unidirectional stream.
         * @param max
         * @return
         */
        Builder maxOpenPeerInitiatedUnidirectionalStreams(int max);

        Builder version(QuicVersion version);

        Builder initialVersion(QuicVersion version);

        Builder preferredVersion(QuicVersion version);

        Builder logger(Logger log);

        Builder sessionTicket(QuicSessionTicket ticket);

        Builder sessionTicket(byte[] ticketData);

        Builder proxy(String host);

        Builder secrets(Path secretsFile);

        Builder uri(URI uri);

        Builder host(String host);

        Builder port(int port);

        Builder preferIPv4();

        Builder preferIPv6();

        Builder connectionIdLength(int length);

        Builder initialRtt(int initialRtt);

        Builder cipherSuite(TlsConstants.CipherSuite cipherSuite);

        /**
         * Sets the named groups to generate a key share for in the client hello. The groups are used in the order of
         * the given list, the first being the most preferred.
         * Offering a key share for more than one group avoids the extra round trip of a HelloRetryRequest when the
         * server does not support the client's first choice.
         * The preferred groups are automatically advertised as supported groups too; when supported groups are set
         * explicitly with {@link #supportedGroups(List)}, each preferred group must be one of them and the order of
         * the preferred groups must match the order of the supported groups.
         * If no preferred group is set, the first supported group is used (or a default, when supported groups are not
         * set either).
         * Calling this method more than once replaces the groups set by the previous call.
         * @param namedGroups  the named groups to generate a key share for, must not be empty
         * @return  the builder
         */
        Builder preferredGroups(List<TlsConstants.NamedGroup> namedGroups);

        /**
         * Sets the named groups to advertise as supported groups in the client hello. The groups are advertised in the
         * order of the given list, the first being the most preferred.
         * If no supported group is set, the preferred groups are used as supported groups (or a default, when
         * preferred groups are not set either).
         * Calling this method more than once replaces the groups set by the previous call.
         * @param namedGroups  the named groups to advertise as supported, must not be empty
         * @return  the builder
         */
        Builder supportedGroups(List<TlsConstants.NamedGroup> namedGroups);

        Builder noServerCertificateCheck();

        /**
         * Sets the custom trust store that will be used to validate the server's certificate.
         * If not set, the default trust store of the Java runtime environment will be used.
         * This is an alternative for calling {@link #customTrustManager(X509TrustManager)}, under the hood both
         * methods achieve the same result.
         * @param customTrustStore
         * @return  the builder
         */
        Builder customTrustStore(KeyStore customTrustStore);

        /**
         * Sets the custom trust manager that will be used to validate the server's certificate.
         * If not set, the default trust store of the Java runtime environment will be used.
         * This is an alternative for calling {@link #customTrustStore(KeyStore)}, under the hood both
         * methods achieve the same result.
         * @param customTrustManager
         * @return  the builder
         */
        Builder customTrustManager(X509TrustManager customTrustManager);

        Builder quantumReadinessTest(int nrOfDummyBytes);

        Builder clientCertificate(X509Certificate certificate);

        Builder clientCertificateKey(PrivateKey privateKey);

        /**
         * Sets the key manager that will be used to authenticate the client to the server. The key manager should
         * contain the client's private key(s) and certificate(s) it wants to use for authentication.
         * The first certificate whose issuer corresponds to one of the authorities indicated by the server is used.
         * If none matches or if the server did not send the "certificate_authorities" extension, the first certificate
         * in the key store is used.
         * @param   keyManager
         * @return  the builder
         */
        Builder clientKeyManager(X509ExtendedKeyManager keyManager);

        /**
         * Sets the key manager that will be used to authenticate the client to the server. The key manager should
         * contain the client's private key(s) and certificate(s) it wants to use for authentication.
         * The first certificate whose issuer corresponds to one of the authorities indicated by the server is used.
         * If none matches or if the server did not send the "certificate_authorities" extension, the first certificate
         * in the key store is used.
         * @param   keyManager
         * @return  the builder
         */
        Builder clientKeyManager(KeyStore keyManager);

        /**
         * Sets the password for the client's private key.
         * @param keyPassword
         * @return  the builder
         */
        Builder clientKey(String keyPassword);

        Builder socketFactory(DatagramSocketFactory socketFactory);

        /**
         * Enable the datagram extension (RFC 9221).
         * @return  the builder
         */
        Builder enableDatagramExtension();

        /**
         * Enable the Stream Resets with Partial Delivery extension
         * (https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-07.html)
         * @return  the builder
         */
        Builder enableReliableStreamReset();
    }

}
