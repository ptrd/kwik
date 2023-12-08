/*
 * Copyright © 2023 Peter Doornbosch
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
package net.luminis.quic.stream;

import java.nio.ByteBuffer;

/**
 * A receive buffer that buffers incoming stream data until it is read,
 * ensuring that readers can only read data in the right order and without gaps.
 */
public interface ReceiveBuffer {

    /**
     * Add a stream frame to this stream. The frame can contain any number of bytes positioned anywhere in the stream;
     * the read method will take care of returning stream bytes in the right order, without gaps.
     * @param  frame the stream frame to add
     * @return true if the frame adds new readable bytes to this stream, false otherwise. Readable means that the newly
     * added bytes can be consumed by the read method; i.e. there are no gaps between the current read position and the
     * bytes that are added by the frame.
     */
    boolean add(StreamElement frame);

    /**
     * Returns the number of bytes that can be read from this stream.
     * @return the number bytes that can be read (can be 0); if the end of the stream has been reached, 0 is returned.
     */
    long bytesAvailable();

    /**
     * Returns whether all bytes of the stream have been read.
     * As long as the end of the stream is not yet known, this method will return false.
     * For streams that have no defined end (QUIC crypto streams), this method will always return false.
     * @return
     */
    boolean allRead();

    /**
     * Read bytes from the buffer.
     * The number of bytes that is actually read is the minimum of the number of bytes that
     * can be written to the buffer parameter (i.e. buffer.limit() - buffer.position())
     * and the number of bytes available on the stream.
     * If no bytes are available because the end of the stream has been reached, the value -1 is returned.
     * This method never blocks: when no bytes are available, 0 is returned.
     * @param buffer  the buffer to write the bytes to
     * @return  number of bytes read (can be 0), or -1 if the end of the stream has been reached.
     */
    int read(ByteBuffer buffer);

    /**
     * Returns whether all data of the stream is received (irrespective of whether it is read).
     * For streams that have no defined end (e.g. crypto streams), this method always returns false.
     *
     * @return  true if all data has been received, false otherwise
     */
    boolean allDataReceived();

    /**
     * Returns the position in the stream up to where stream bytes are read.
     * @return
     */
    long readOffset();

    /**
     * Discard all data that is currently buffered.
     */
    void discardAllData();
}
