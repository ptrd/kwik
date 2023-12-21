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

import static net.luminis.quic.server.Constants.MAXIMUM_CONNECTION_ID_LENGTH;
import static net.luminis.quic.server.Constants.MINIMUM_CONNECTION_ID_LENGTH;


public class ServerConfig implements ConnectionConfig {

    private static final int DEFAULT_MAX_IDLE_TIMEOUT = 30_000;
    private static final int DEFAULT_CONNECTION_ID_LENGTH = 8;

    public enum RetryRequired { Always, Never }

    private int maxIdleTimeout = DEFAULT_MAX_IDLE_TIMEOUT;
    private int maxOpenUnidirectionalStreams;
    private int maxOpenBidirectionalStreams;
    private long maxConnectionBufferSize;
    private long maxUnidirectionalStreamBufferSize;
    private long maxBidirectionalStreamBufferSize;
    private RetryRequired retryRequired;
    private int connectionIdLength = DEFAULT_CONNECTION_ID_LENGTH;

    private ServerConfig() {
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

    public int connectionIdLength() {
        return connectionIdLength;
    }

    public RetryRequired retryRequired() {
        return retryRequired;
    }

    public int initialRtt() {
        return 100;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private ServerConfig config = new ServerConfig();

        public ServerConfig build() {
            return config;
        }

        public Builder maxIdleTimeoutInSeconds(int timeoutInSeconds) {
            if (timeoutInSeconds <= 0) {
                throw new IllegalArgumentException();
            }
            config.maxIdleTimeout = timeoutInSeconds * 1000;
            return this;
        }

        public Builder maxConnectionBufferSize(long size) {
            if (size < 0) {
                throw new IllegalArgumentException();
            }
            config.maxConnectionBufferSize = size;
            return this;
        }

        public Builder maxUnidirectionalStreamBufferSize(int size) {
            if (size < 0) {
                throw new IllegalArgumentException();
            }
            config.maxUnidirectionalStreamBufferSize = size;
            return this;
        }

        public Builder maxBidirectionalStreamBufferSize(int size) {
            if (size < 0) {
                throw new IllegalArgumentException();
            }
            config.maxBidirectionalStreamBufferSize = size;
            return this;
        }

        public Builder maxOpenUnidirectionalStreams(int max) {
            if (max < 0) {
                throw new IllegalArgumentException();
            }
            config.maxOpenUnidirectionalStreams = max;
            return this;
        }

        public Builder maxOpenBidirectionalStreams(int max) {
            if (max < 0) {
                throw new IllegalArgumentException();
            }
            config.maxOpenBidirectionalStreams = max;
            return this;
        }

        public Builder retryRequired(boolean retryRequired) {
            config.retryRequired = retryRequired? RetryRequired.Always : RetryRequired.Never;
            return this;
        }

        public Builder retryRequired(RetryRequired retryRequired) {
            config.retryRequired = retryRequired;
            return this;
        }

        public Builder connectionIdLength(int connectionIdLength) {
            if (connectionIdLength < MINIMUM_CONNECTION_ID_LENGTH || connectionIdLength > MAXIMUM_CONNECTION_ID_LENGTH) {
                throw new IllegalArgumentException("Connection ID length must be between " + MINIMUM_CONNECTION_ID_LENGTH + " and " + MAXIMUM_CONNECTION_ID_LENGTH);
            }
            config.connectionIdLength = connectionIdLength;
            return this;
        }
    }
}
