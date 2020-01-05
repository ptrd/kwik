/*
 * Copyright © 2019, 2020 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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
package net.luminis.quic;

import static net.luminis.quic.ConnectionIdStatus.IN_USE;
import static net.luminis.quic.ConnectionIdStatus.NEW;

public class ConnectionIdInfo {
    byte[] connectionId;
    ConnectionIdStatus connectionIdStatus;

    ConnectionIdInfo(byte[] connectionId) {
        this.connectionId = connectionId;
        connectionIdStatus = NEW;
    }

    ConnectionIdInfo(byte[] connectionId, ConnectionIdStatus status) {
        this.connectionId = connectionId;
        connectionIdStatus = status;
    }

    public byte[] getConnectionId() {
        return connectionId;
    }

    public ConnectionIdStatus getConnectionIdStatus() {
        return connectionIdStatus;
    }

    public void setStatus(ConnectionIdStatus newStatus) {
        connectionIdStatus = newStatus;
    }
}

