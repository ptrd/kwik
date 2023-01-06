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

import java.time.Duration;
import java.util.function.Consumer;


public interface QuicConnection {

    Version getQuicVersion();

    void setMaxAllowedBidirectionalStreams(int max);

    void setMaxAllowedUnidirectionalStreams(int max);

    void setDefaultStreamReceiveBufferSize(long size);

    QuicStream createStream(boolean bidirectional);

    void setPeerInitiatedStreamCallback(Consumer<QuicStream> streamConsumer);

    void close();

    /**
     * Closes the connection and wait for the close to complete. This close method should be used when called just before
     * the JVM shuts down, to enable the QUIC connection to close properly (send connection close frame and retransmit
     * if lost).
     */
    void closeAndWait();

    /**
     * Closes the connection and wait for the close to complete. This close method should be used when called just before
     * the JVM shuts down, to enable the QUIC connection to close properly (send connection close frame and retransmit
     * if lost).
     *
     * @param maxWait     maximum time to wait before returning.
     */
    void closeAndWait(Duration maxWait);

    void close(QuicConstants.TransportErrorCode applicationError, String errorReason);

    Statistics getStats();
}
