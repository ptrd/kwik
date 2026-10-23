/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.core.stream;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Keeps track of the (estimated) memory overhead of all stream receive buffers of a connection, to limit the total
 * amount of memory a peer can make the connection use for buffering received stream data.
 * Thread-safe, as receive buffers update the overhead from both the receiver thread and application (reader) threads.
 */
public class ConnectionMemoryBudget {

    private final AtomicLong overhead = new AtomicLong();
    private volatile long maxOverhead;

    /**
     * Sets the connection buffer size, which determines the maximum overhead.
     * @param connectionBufferSize  the maximum amount of stream data that can be buffered for the connection at any
     *                              time (as enforced by connection flow control)
     */
    void setConnectionBufferSize(long connectionBufferSize) {
        // As the amount of buffered data never exceeds the connection buffer size, the remainder is available for overhead.
        maxOverhead = (ReceiveBufferImpl.MAX_MEMORY_FACTOR - 1) * connectionBufferSize;
    }

    void update(long delta) {
        overhead.addAndGet(delta);
    }

    boolean isExceeded() {
        return overhead.get() > maxOverhead;
    }

    long getOverhead() {
        return overhead.get();
    }
}
