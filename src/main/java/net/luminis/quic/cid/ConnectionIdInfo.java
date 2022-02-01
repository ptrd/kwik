/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic.cid;


public class ConnectionIdInfo {

    final private int sequenceNumber;
    final private byte[] connectionId;
    private ConnectionIdStatus connectionIdStatus;
    private final byte[] statelessResetToken;


    ConnectionIdInfo(int sequenceNumber, byte[] connectionId, ConnectionIdStatus status) {
        this.sequenceNumber = sequenceNumber;
        this.connectionId = connectionId;
        connectionIdStatus = status;
        this.statelessResetToken = null;
    }

    ConnectionIdInfo(int sequenceNumber, byte[] connectionId, ConnectionIdStatus status, byte[] statelessResetToken) {
        this.sequenceNumber = sequenceNumber;
        this.connectionId = connectionId;
        connectionIdStatus = status;
        this.statelessResetToken = statelessResetToken;
    }

    public ConnectionIdInfo addStatelessResetToken(byte[] statelessResetToken) {
        return new ConnectionIdInfo(sequenceNumber, connectionId, connectionIdStatus, statelessResetToken);
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    public byte[] getConnectionId() {
        return connectionId;
    }

    public ConnectionIdStatus getConnectionIdStatus() {
        return connectionIdStatus;
    }

    public byte[] getStatelessResetToken() {
        return statelessResetToken;
    }

    protected void setStatus(ConnectionIdStatus newStatus) {
        connectionIdStatus = newStatus;
    }
}

