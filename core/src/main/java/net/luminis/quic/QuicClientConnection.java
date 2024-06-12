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
package net.luminis.quic;

import net.luminis.quic.impl.QuicClientConnectionImpl;
import net.luminis.quic.log.Logger;
import net.luminis.tls.TlsConstants;

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

        Builder proxy(String host);

        Builder secrets(Path secretsFile);

        Builder uri(URI uri);

        Builder connectionIdLength(int length);

        Builder initialRtt(int initialRtt);

        Builder cipherSuite(TlsConstants.CipherSuite cipherSuite);

        Builder noServerCertificateCheck();

        Builder customTrustStore(KeyStore customTrustStore);

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
        Builder clientKeyManager(KeyStore keyManager);

        /**
         * Sets the password for the client's private key.
         * @param keyPassword
         * @return
         */
        Builder clientKey(String keyPassword);

        Builder socketFactory(DatagramSocketFactory socketFactory);
    }

}
