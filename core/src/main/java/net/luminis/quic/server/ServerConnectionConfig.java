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

import net.luminis.quic.ConnectionConfig;
import net.luminis.quic.server.impl.ServerConnectionConfigImpl;

public interface ServerConnectionConfig extends ConnectionConfig {

    enum RetryRequired { Always, Never }

    int connectionIdLength();

    RetryRequired retryRequired();

    int initialRtt();

    ServerConnectionConfig merge(ApplicationProtocolSettings protocol);

    static Builder builder() {
        return new ServerConnectionConfigImpl.BuilderImpl();
    }

    interface Builder {
        ServerConnectionConfig build();

        Builder maxIdleTimeoutInSeconds(int timeoutInSeconds);

        Builder maxIdleTimeout(int milliSeconds);

        Builder maxConnectionBufferSize(long size);

        Builder maxUnidirectionalStreamBufferSize(long size);

        Builder maxBidirectionalStreamBufferSize(long size);

        Builder maxOpenPeerInitiatedUnidirectionalStreams(int max);

        Builder maxOpenPeerInitiatedBidirectionalStreams(int max);

        Builder retryRequired(boolean retryRequired);

        Builder retryRequired(RetryRequired retryRequired);

        Builder connectionIdLength(int connectionIdLength);

        Builder maxTotalPeerInitiatedUnidirectionalStreams(long max);

        Builder maxTotalPeerInitiatedBidirectionalStreams(long max);

        Builder useStrictSmallestAllowedMaximumDatagramSize(boolean value);
    }
}
