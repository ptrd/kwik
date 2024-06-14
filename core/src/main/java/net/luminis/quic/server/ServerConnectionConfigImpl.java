/*
 * Copyright © 2023, 2024 Peter Doornbosch
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

import static java.lang.Long.max;
import static java.lang.Long.min;
import static net.luminis.quic.server.ApplicationProtocolSettings.NOT_SPECIFIED;
import static net.luminis.quic.server.Constants.MAXIMUM_CONNECTION_ID_LENGTH;
import static net.luminis.quic.server.Constants.MINIMUM_CONNECTION_ID_LENGTH;


public class ServerConnectionConfigImpl implements ServerConnectionConfig {

    private static final int DEFAULT_MAX_IDLE_TIMEOUT = 30_000;
    private static final int DEFAULT_CONNECTION_ID_LENGTH = 8;

    private int maxIdleTimeout = DEFAULT_MAX_IDLE_TIMEOUT;
    private int maxOpenUnidirectionalStreams;
    private long maxTotalUnidirectionalStreams = Long.MAX_VALUE;
    private int maxOpenBidirectionalStreams;
    private long maxTotalBidirectionalStreams = Long.MAX_VALUE;
    private long maxConnectionBufferSize;
    private long maxUnidirectionalStreamBufferSize;
    private long maxBidirectionalStreamBufferSize;
    private ServerConnectionConfig.RetryRequired retryRequired;
    private int connectionIdLength = DEFAULT_CONNECTION_ID_LENGTH;

    private ServerConnectionConfigImpl() {
    }

    @Override
    public int maxIdleTimeout() {
        return maxIdleTimeout;
    }

    @Override
    public int maxOpenPeerInitiatedUnidirectionalStreams() {
        return maxOpenUnidirectionalStreams;
    }

    @Override
    public long maxTotalPeerInitiatedUnidirectionalStreams() {
        return maxTotalUnidirectionalStreams;
    }

    @Override
    public int maxOpenPeerInitiatedBidirectionalStreams() {
        return maxOpenBidirectionalStreams;
    }

    @Override
    public long maxTotalPeerInitiatedBidirectionalStreams() {
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

    public int connectionIdLength() {
        return connectionIdLength;
    }

    public RetryRequired retryRequired() {
        return retryRequired;
    }

    public int initialRtt() {
        return 100;
    }

    @Override
    public ServerConnectionConfig merge(ApplicationProtocolSettings protocol) {
        ServerConnectionConfig.Builder configBuilder = ServerConnectionConfig.builder();

        configBuilder.maxIdleTimeout(this.maxIdleTimeout());

        long maxUnidirectionalStreamBufferSize = limitValue(protocol.minUnidirectionalStreamReceiverBufferSize(),
                protocol.maxUnidirectionalStreamReceiverBufferSize(), this.maxUnidirectionalStreamBufferSize());
        configBuilder.maxUnidirectionalStreamBufferSize(maxUnidirectionalStreamBufferSize);

        long maxBidirectionalStreamBufferSize = limitValue(protocol.minBidirectionalStreamReceiverBufferSize(),
                protocol.maxBidirectionalStreamReceiverBufferSize(), this.maxBidirectionalStreamBufferSize());
        configBuilder.maxBidirectionalStreamBufferSize(maxBidirectionalStreamBufferSize);

        // Connection buffer size must be at least as large as the largest stream buffer size.
        long maxConnectionBufferSize = max(max(maxUnidirectionalStreamBufferSize, maxBidirectionalStreamBufferSize), this.maxConnectionBufferSize());
        configBuilder.maxConnectionBufferSize(maxConnectionBufferSize);

        configBuilder.maxOpenPeerInitiatedUnidirectionalStreams(limitValue(0,
                protocol.maxConcurrentPeerInitiatedUnidirectionalStreams(), this.maxOpenPeerInitiatedUnidirectionalStreams()));

        configBuilder.maxOpenPeerInitiatedBidirectionalStreams(limitValue(0,
                protocol.maxConcurrentPeerInitiatedBidirectionalStreams(), this.maxOpenPeerInitiatedBidirectionalStreams()));

        configBuilder.maxTotalPeerInitiatedUnidirectionalStreams(protocol.maxTotalPeerInitiatedUnidirectionalStreams());
        configBuilder.maxTotalPeerInitiatedBidirectionalStreams(protocol.maxTotalPeerInitiatedBidirectionalStreams());
        configBuilder.retryRequired(this.retryRequired());
        configBuilder.connectionIdLength(this.connectionIdLength());

        return configBuilder.build();
    }

    private long limitValue(int minimumValue, long maximumValue, long currentValue) {
        if (minimumValue == NOT_SPECIFIED) {
            minimumValue = 0;
        }
        if (maximumValue == NOT_SPECIFIED) {
            maximumValue = Long.MAX_VALUE;
        }
        if (minimumValue > maximumValue) {
            throw new IllegalArgumentException();
        }

        long newValue;

        if (minimumValue < 0) {
            throw new IllegalArgumentException();
        }
        newValue = max(minimumValue, currentValue);

        if (maximumValue < 0) {
            throw new IllegalArgumentException();
        }
        newValue = min(newValue, maximumValue);

        return newValue;
    }

    private int limitValue(int minimumValue, int maximumValue, int currentValue) {
        if (minimumValue == NOT_SPECIFIED) {
            minimumValue = 0;
        }
        if (maximumValue == NOT_SPECIFIED) {
            maximumValue = Integer.MAX_VALUE;
        }
        if (minimumValue > maximumValue) {
            throw new IllegalArgumentException();
        }

        int newValue;

        if (minimumValue < 0) {
            throw new IllegalArgumentException();
        }
        newValue = Integer.max(minimumValue, currentValue);

        if (maximumValue < 0) {
            throw new IllegalArgumentException();
        }
        newValue = Integer.min(newValue, maximumValue);

        return newValue;
    }

    public static ServerConnectionConfig.Builder builder() {
        return new BuilderImpl();
    }

    public static class BuilderImpl implements ServerConnectionConfig.Builder {

        private ServerConnectionConfigImpl config = new ServerConnectionConfigImpl();

        @Override
        public ServerConnectionConfig build() {
            if (config.maxConnectionBufferSize < config.maxUnidirectionalStreamBufferSize) {
                throw new IllegalArgumentException("Connection buffer size can't be less then unidirectional stream buffer size");
            }
            if (config.maxConnectionBufferSize < config.maxBidirectionalStreamBufferSize) {
                throw new IllegalArgumentException("Connection buffer size can't be less then bidirectional stream buffer size");
            }
            return config;
        }

        @Override
        public Builder maxIdleTimeoutInSeconds(int timeoutInSeconds) {
            if (timeoutInSeconds <= 0) {
                throw new IllegalArgumentException();
            }
            config.maxIdleTimeout = timeoutInSeconds * 1000;
            return this;
        }

        @Override
        public Builder maxIdleTimeout(int milliSeconds) {
            if (milliSeconds <= 0) {
                throw new IllegalArgumentException();
            }
            config.maxIdleTimeout = milliSeconds;
            return this;
        }

        @Override
        public Builder maxConnectionBufferSize(long size) {
            if (size < 0) {
                throw new IllegalArgumentException();
            }
            config.maxConnectionBufferSize = size;
            return this;
        }

        @Override
        public Builder maxUnidirectionalStreamBufferSize(long size) {
            if (size < 0) {
                throw new IllegalArgumentException();
            }
            config.maxUnidirectionalStreamBufferSize = size;
            return this;
        }

        @Override
        public Builder maxBidirectionalStreamBufferSize(long size) {
            if (size < 0) {
                throw new IllegalArgumentException();
            }
            config.maxBidirectionalStreamBufferSize = size;
            return this;
        }

        @Override
        public Builder maxOpenPeerInitiatedUnidirectionalStreams(int max) {
            if (max < 0) {
                throw new IllegalArgumentException();
            }
            config.maxOpenUnidirectionalStreams = max;
            return this;
        }

        @Override
        public Builder maxOpenPeerInitiatedBidirectionalStreams(int max) {
            if (max < 0) {
                throw new IllegalArgumentException();
            }
            config.maxOpenBidirectionalStreams = max;
            return this;
        }

        @Override
        public Builder retryRequired(boolean retryRequired) {
            config.retryRequired = retryRequired? RetryRequired.Always : RetryRequired.Never;
            return this;
        }

        @Override
        public Builder retryRequired(RetryRequired retryRequired) {
            config.retryRequired = retryRequired;
            return this;
        }

        @Override
        public Builder connectionIdLength(int connectionIdLength) {
            if (connectionIdLength < MINIMUM_CONNECTION_ID_LENGTH || connectionIdLength > MAXIMUM_CONNECTION_ID_LENGTH) {
                throw new IllegalArgumentException("Connection ID length must be between " + MINIMUM_CONNECTION_ID_LENGTH + " and " + MAXIMUM_CONNECTION_ID_LENGTH);
            }
            config.connectionIdLength = connectionIdLength;
            return this;
        }

        @Override
        public Builder maxTotalPeerInitiatedUnidirectionalStreams(long max) {
            config.maxTotalUnidirectionalStreams = max;
            return this;
        }

        @Override
        public Builder maxTotalPeerInitiatedBidirectionalStreams(long max) {
            config.maxTotalBidirectionalStreams = max;
            return this;
        }
    }
}
