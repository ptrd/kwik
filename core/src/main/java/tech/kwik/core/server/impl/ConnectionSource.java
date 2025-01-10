/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.server.impl;

import tech.kwik.core.util.Bytes;
import tech.kwik.core.util.SecureHash;

import java.util.Arrays;

public class ConnectionSource {

    private final byte[] dcid;
    private final int hashCode;

    public ConnectionSource(byte[] dcid, SecureHash secureHash) {
        this.dcid = dcid;
        hashCode = secureHash.generateHashCode(dcid);
    }

    @Override
    public int hashCode() {
        return hashCode;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ConnectionSource) {
            return Arrays.equals(this.dcid, ((ConnectionSource) obj).dcid);
        }
        else {
            return false;
        }
    }

    @Override
    public String toString() {
        return "ConnectionSource[" + Bytes.bytesToHex(dcid) + "]";
    }
}
