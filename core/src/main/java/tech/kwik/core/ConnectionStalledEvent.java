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
package tech.kwik.core;

import java.time.Duration;

/**
 * Event that indicates that the connection might be stalled: a probe timeout occurred, i.e. no acknowledgement was
 * received in time for the ack-eliciting packets sent.
 */
public class ConnectionStalledEvent {

    private final QuicConnection connection;
    private final int probeTimeoutCount;
    private final Duration stalledDuration;

    public ConnectionStalledEvent(QuicConnection connection, int probeTimeoutCount, Duration stalledDuration) {
        this.connection = connection;
        this.probeTimeoutCount = probeTimeoutCount;
        this.stalledDuration = stalledDuration;
    }

    QuicConnection connection() {
        return connection;
    }

    /**
     * @return  the number of consecutive probe timeouts, i.e. without receiving an acknowledgement in between.
     */
    public int probeTimeoutCount() {
        return probeTimeoutCount;
    }

    /**
     * @return  the time elapsed since the connection stalled, i.e. since the time the last ack-eliciting packet before
     * the first probe timeout (of the current series of consecutive probe timeouts) was sent.
     */
    public Duration stalledDuration() {
        return stalledDuration;
    }
}
