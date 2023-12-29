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
package net.luminis.quic.core;

import net.luminis.quic.ConnectionConfig;

public class ClientConnectionConfig implements ConnectionConfig {

    private int maxIdleTimeout;
    private int maxOpenUnidirectionalStreams;
    private int maxOpenBidirectionalStreams;
    private long maxConnectionBufferSize;
    private long maxUnidirectionalStreamBufferSize;
    private long maxBidirectionalStreamBufferSize;
    private int activeConnectionIdLimit;
    private int maxUdpPayloadSize;

    @Override
    public int maxIdleTimeout() {
        return maxIdleTimeout;
    }

    void setMaxIdleTimeout(int maxIdleTimeout) {
        this.maxIdleTimeout = maxIdleTimeout;
    }

    @Override
    public int maxOpenPeerInitiatedUnidirectionalStreams() {
        return maxOpenUnidirectionalStreams;
    }

    void setMaxOpenPeerInitiatedUnidirectionalStreams(int maxOpenUnidirectionalStreams) {
        this.maxOpenUnidirectionalStreams = maxOpenUnidirectionalStreams;
    }

    @Override
    public long maxTotalPeerInitiatedUnidirectionalStreams() {
        return Long.MAX_VALUE;
    }

    @Override
    public int maxOpenPeerInitiatedBidirectionalStreams() {
        return maxOpenBidirectionalStreams;
    }

    void setMaxOpenPeerInitiatedBidirectionalStreams(int maxOpenBidirectionalStreams) {
        this.maxOpenBidirectionalStreams = maxOpenBidirectionalStreams;
    }

    @Override
    public long maxTotalPeerInitiatedBidirectionalStreams() {
        return Long.MAX_VALUE;
    }

    @Override
    public long maxConnectionBufferSize() {
        return maxConnectionBufferSize;
    }

    void setMaxConnectionBufferSize(long maxConnectionBufferSize) {
        this.maxConnectionBufferSize = maxConnectionBufferSize;
    }

    @Override
    public long maxUnidirectionalStreamBufferSize() {
        return maxUnidirectionalStreamBufferSize;
    }

    void setMaxUnidirectionalStreamBufferSize(long maxUnidirectionalStreamBufferSize) {
        this.maxUnidirectionalStreamBufferSize = maxUnidirectionalStreamBufferSize;
    }

    @Override
    public long maxBidirectionalStreamBufferSize() {
        return maxBidirectionalStreamBufferSize;
    }

    void setMaxBidirectionalStreamBufferSize(long maxBidirectionalStreamBufferSize) {
        this.maxBidirectionalStreamBufferSize = maxBidirectionalStreamBufferSize;
    }

    public int getActiveConnectionIdLimit() {
        return activeConnectionIdLimit;
    }

    public void setActiveConnectionIdLimit(int limit) {
        activeConnectionIdLimit = limit;
    }

    public int getMaxUdpPayloadSize() {
        return maxUdpPayloadSize;
    }

    public void setMaxUdpPayloadSize(int maxSize) {
        maxUdpPayloadSize = maxSize;
    }
}
