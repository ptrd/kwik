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
package net.luminis.quic.server;

import net.luminis.quic.ConnectionConfig;

public class ServerConfig implements ConnectionConfig {

    private int maxIdleTimeout;
    private int maxOpenUnidirectionalStreams;
    private int maxOpenBidirectionalStreams;
    private long maxConnectionBufferSize;
    private long maxUnidirectionalStreamBufferSize;
    private long maxBidirectionalStreamBufferSize;

    private ServerConfig(int maxIdleTimeout, int maxOpenUnidirectionalStreams, int maxOpenBidirectionalStreams,
                         long maxConnectionBufferSize, long maxUnidirectionalStreamBufferSize, long maxBidirectionalStreamBufferSize) {
        this.maxIdleTimeout = maxIdleTimeout;
        this.maxOpenUnidirectionalStreams = maxOpenUnidirectionalStreams;
        this.maxOpenBidirectionalStreams = maxOpenBidirectionalStreams;
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
    public int maxOpenBidirectionalStreams() {
        return maxOpenBidirectionalStreams;
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

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private int maxIdleTimeout = 30 * 1000;
        private int maxOpenUnidirectionalStreams = 0;
        private int maxOpenBidirectionalStreams = 0;
        private long maxConnectionBufferSize;
        private long maxUnidirectionalStreamBufferSize;
        private long maxBidirectionalStreamBufferSize;

        public ServerConfig build() {
            return new ServerConfig(
                    maxIdleTimeout,
                    maxOpenUnidirectionalStreams,
                    maxOpenBidirectionalStreams,
                    maxConnectionBufferSize,
                    maxUnidirectionalStreamBufferSize,
                    maxBidirectionalStreamBufferSize);
        }

        public Builder maxIdleTimeoutInSeconds(int timeoutInSeconds) {
            this.maxIdleTimeout = timeoutInSeconds * 1000;
            return this;
        }

        public Builder maxConnectionBufferSize(long size) {
            this.maxConnectionBufferSize = size;
            return this;
        }

        public Builder maxUnidirectionalStreamBufferSize(int size) {
            this.maxUnidirectionalStreamBufferSize = size;
            return this;
        }

        public Builder maxBidirectionalStreamBufferSize(int size) {
            this.maxBidirectionalStreamBufferSize = size;
            return this;
        }

        public Builder maxOpenUnidirectionalStreams(int max) {
            this.maxOpenUnidirectionalStreams = max;
            return this;
        }

        public Builder maxOpenBidirectionalStreams(int max) {
            this.maxOpenBidirectionalStreams = max;
            return this;
        }
    }
}
