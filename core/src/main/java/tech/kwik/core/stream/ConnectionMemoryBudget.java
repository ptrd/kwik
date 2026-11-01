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
 * <p>
 * When the overhead of all buffers together is high (see {@link #overheadIsHigh()}), all receive buffers compact small
 * contiguous frames into chunks; without this, in-order traffic with small frames spread over many streams would
 * exceed the budget before any of the buffers would start compacting on its own. Once compacting, the overhead only
 * grows by the chunks: per buffer at most one partly filled chunk (whose unused capacity counts as overhead) plus the
 * per-frame overhead of each chunk. Hence, in-order traffic stays within the budget as long as the number of streams
 * times the chunk size is well below half the maximum overhead. For the default server configuration (110 streams,
 * 10 MB connection buffer size) that is about 0.2 MB compared to 5 MB: in-order traffic with 1 to 100 byte frames
 * that uses all connection flow control credit results in about 5.4 to 5.8 MB overhead, whereas small out-of-order
 * frames with gaps in between are stopped when the overhead reaches the maximum of 10 MB.
 * <p>
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

    /**
     * Returns whether the overhead of all receive buffers together is so high that receive buffers should compact
     * (small) contiguous frames and combine adjacent out-of-order frames. Like for a single receive buffer, this starts
     * at half the maximum overhead.
     */
    boolean overheadIsHigh() {
        return overhead.get() > maxOverhead / 2;
    }

    long getOverhead() {
        return overhead.get();
    }
}
