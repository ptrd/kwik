/*
 * Copyright © 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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

import java.io.InputStream;
import java.io.OutputStream;

/**
 * A QUIC stream.
 * <p>
 * https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-34#section-2
 * "Streams in QUIC provide a lightweight, ordered byte-stream abstraction to an application. Streams can be
 *  unidirectional or bidirectional."
 *
 */
public interface QuicStream {

    /**
     * Returns the input stream for reading data sent by the peer.
     *
     * @return  the input stream
     */
    InputStream getInputStream();

    /**
     * Returns the output stream for sending data to the peer.
     *
     * @return  the output stream
     */
    OutputStream getOutputStream();

    /**
     * Returns the stream ID of the stream.
     * <p>
     * https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-34#section-2.1
     * "Streams are identified within a connection by a numeric value, referred to as the stream ID. A stream ID is
     *  a 62-bit integer (0 to 2^62-1) that is unique for all streams on a connection."
     *
     * @return  the stream id; this is an int because Kwik cannot handle more than 2147483647 (<code>Integer.MAX_INT</code>) streams in one connection.
     */
    int getStreamId();

    /**
     * Returns whether this stream is unidirectional.
     *
     * @return  true when unidirectional, false otherwise.
     */
    boolean isUnidirectional();

    /**
     * Returns whether this stream is bidirectional.
     *
     * @return  true when bidirectional, false otherwise.
     */
    default boolean isBidirectional() {
        return !isUnidirectional();
    }

    /**
     * Returns whether this stream is client initiated bidirectional.
     *
     * @return  true when client initiated and bidirectional
     */
    boolean isClientInitiatedBidirectional();

    /**
     * Returns whether this stream is server initiated bidirectional.
     *
     * @return  true when server initiated and bidirectional
     */
    boolean isServerInitiatedBidirectional();

    /**
     * https://www.rfc-editor.org/rfc/rfc9000.html#name-operations-on-streams
     * "On the receiving part of a stream, an application protocol can:
     * - abort reading of the stream and request closure, possibly resulting in a STOP_SENDING frame (Section 19.5)."
     *
     * @param applicationProtocolErrorCode
     */
    void abortReading(long applicationProtocolErrorCode);

    /**
     * https://www.rfc-editor.org/rfc/rfc9000.html#name-operations-on-streams
     * "On the sending part of a stream, an application protocol can:
     *  - reset the stream (abrupt termination), resulting in a RESET_STREAM frame (Section 19.4) if the stream was not
     *    already in a terminal state."
     *
     * @param applicationProtocolErrorCode
     */
    void resetStream(long applicationProtocolErrorCode);

    /**
     * @deprecated use {@link #abortReading(long)} instead
     * @param applicationProtocolErrorCode
     */
    @Deprecated
    default void closeInput(long applicationProtocolErrorCode) {
        abortReading(applicationProtocolErrorCode);
    }
}
