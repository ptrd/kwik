/*
 * Copyright © 2020, 2021, 2022 Peter Doornbosch
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

import net.luminis.quic.QuicStream;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.List;


public interface QuicClientConnection extends QuicConnection {

    void connect(int connectionTimeout, String alpn) throws IOException;

    void connect(int connectionTimeout, String alpn, TransportParameters transportParameters) throws IOException;

    List<QuicStream> connect(int connectionTimeout, String applicationProtocol, TransportParameters transportParameters, List<StreamEarlyData> earlyData) throws IOException;

    void keepAlive(int seconds);

    List<QuicSessionTicket> getNewSessionTickets();

    InetSocketAddress getLocalAddress();

    InetSocketAddress getServerAddress();

    List<X509Certificate> getServerCertificateChain();

    boolean isConnected();

    class StreamEarlyData {
        byte[] data;
        boolean closeOutput;

        public StreamEarlyData(byte[] data, boolean closeImmediately) {
            this.data = data;
            closeOutput = closeImmediately;
        }
    }
}
