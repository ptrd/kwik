/*
 * Copyright © 2020 Peter Doornbosch
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
package net.luminis.quic;

import net.luminis.quic.stream.QuicStream;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.function.Consumer;


public interface QuicConnection {

    void setMaxAllowedBidirectionalStreams(int max);

    void setMaxAllowedUnidirectionalStreams(int max);

    void setServerStreamCallback(Consumer<QuicStream> streamProcessor);

    void setDefaultStreamReceiveBufferSize(long size);

    void connect(int connectionTimeout) throws IOException;

    void connect(int connectionTimeout, TransportParameters transportParameters) throws IOException;

    List<QuicStream> connect(int connectionTimeout, String applicationProtocol, TransportParameters transportParameters, List<StreamEarlyData> earlyData) throws IOException;

    void keepAlive(int seconds);

    QuicStream createStream(boolean bidirectional);

    List<QuicSessionTicket> getNewSessionTickets();

    void close();

    Statistics getStats();

    InetSocketAddress getLocalAddress();

    class StreamEarlyData {
        byte[] data;
        boolean closeOutput;

        public StreamEarlyData(byte[] data, boolean closeImmediately) {
            this.data = data;
            closeOutput = closeImmediately;
        }
    }
}

