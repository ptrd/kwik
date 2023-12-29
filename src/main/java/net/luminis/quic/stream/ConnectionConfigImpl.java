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

import net.luminis.quic.ConnectionConfig;

public class ConnectionConfigImpl implements ConnectionConfig {

    private final int maxIdleTimeout;
    private final int maxOpenUnidirectionalStreams;
    private final long maxTotalUnidirectionalStreams;
    private final int maxOpenBidirectionalStreams;
    private final long maxTotalBidirectionalStreams;
    private final long maxConnectionBufferSize;
    private final long maxUnidirectionalStreamBufferSize;
    private final long maxBidirectionalStreamBufferSize;

    public static ConnectionConfig cloneWithMaxUnidirectionalStreamReceiveBufferSize(ConnectionConfig config, long maxUnidirectionalStreamBufferSize) {
        return new ConnectionConfigImpl(
                config.maxIdleTimeout(),
                config.maxOpenUnidirectionalStreams(),
                config.maxTotalUnidirectionalStreams(),
                config.maxOpenBidirectionalStreams(),
                config.maxTotalBidirectionalStreams(),
                config.maxConnectionBufferSize(),
                maxUnidirectionalStreamBufferSize,
                config.maxBidirectionalStreamBufferSize());
    }

    public static ConnectionConfig cloneWithMaxBidirectionalStreamReceiveBufferSize(ConnectionConfig config, long maxBidirectionalStreamBufferSize) {
        return new ConnectionConfigImpl(
                config.maxIdleTimeout(),
                config.maxOpenUnidirectionalStreams(),
                config.maxTotalUnidirectionalStreams(),
                config.maxOpenBidirectionalStreams(),
                config.maxTotalBidirectionalStreams(),
                config.maxConnectionBufferSize(),
                config.maxUnidirectionalStreamBufferSize(),
                maxBidirectionalStreamBufferSize);
    }

    private ConnectionConfigImpl(int maxIdleTimeout,
                                 int maxOpenUnidirectionalStreams, long maxTotalUnidirectionalStreams,
                                 int maxOpenBidirectionalStreams, long maxTotalBidirectionalStreams,
                                 long maxConnectionBufferSize,
                                 long maxUnidirectionalStreamBufferSize, long maxBidirectionalStreamBufferSize) {
        this.maxIdleTimeout = maxIdleTimeout;
        this.maxOpenUnidirectionalStreams = maxOpenUnidirectionalStreams;
        this.maxTotalUnidirectionalStreams = maxTotalUnidirectionalStreams;
        this.maxOpenBidirectionalStreams = maxOpenBidirectionalStreams;
        this.maxTotalBidirectionalStreams = maxTotalBidirectionalStreams;
        this.maxConnectionBufferSize = maxConnectionBufferSize;
        this.maxUnidirectionalStreamBufferSize = maxUnidirectionalStreamBufferSize;
        this.maxBidirectionalStreamBufferSize = maxBidirectionalStreamBufferSize;
    }

    @Override
    public int maxIdleTimeout() {
        return maxIdleTimeout;
    }

    @Override
    public int maxOpenUnidirectionalStreams() {
        return maxOpenUnidirectionalStreams;
    }

    @Override
    public long maxTotalUnidirectionalStreams() {
        return maxTotalUnidirectionalStreams;
    }

    @Override
    public int maxOpenBidirectionalStreams() {
        return maxOpenBidirectionalStreams;
    }

    @Override
    public long maxTotalBidirectionalStreams() {
        return maxTotalBidirectionalStreams;
    }

    @Override
    public long maxConnectionBufferSize() {
        return maxConnectionBufferSize;
    }

    @Override
    public long maxUnidirectionalStreamBufferSize() {
        return maxUnidirectionalStreamBufferSize;
    }

    @Override
    public long maxBidirectionalStreamBufferSize() {
        return maxBidirectionalStreamBufferSize;
    }
}
