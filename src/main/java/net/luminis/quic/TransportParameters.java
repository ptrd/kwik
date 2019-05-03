/*
 * Copyright © 2019 Peter Doornbosch
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

import java.net.InetAddress;

public class TransportParameters {

    private byte[] originalConnectionId;
    private int ackDelayExponent;
    private PreferredAddress preferredAddress;
    private long idleTimeout;

    public byte[] getOriginalConnectionId() {
        return originalConnectionId;
    }

    public void setOriginalConnectionId(byte[] originalConnectionId) {
        this.originalConnectionId = originalConnectionId;
    }

    public void setAckDelayExponent(int ackDelayExponent) {
        this.ackDelayExponent = ackDelayExponent;
    }

    public int getAckDelayExponent() {
        return ackDelayExponent;
    }

    public PreferredAddress getPreferredAddress() {
        return preferredAddress;
    }

    public void setPreferredAddress(PreferredAddress preferredAddress) {
        this.preferredAddress = preferredAddress;
    }

    public long getIdleTimeout() {
        return idleTimeout;
    }

    public void setIdleTimeout(long idleTimeout) {
        this.idleTimeout = idleTimeout;
    }

    public static class PreferredAddress {
        InetAddress ip4;
        int ip4Port;
        InetAddress ip6;
        int ip6Port;
        byte[] connectionId;
        byte[] statelessResetToken;
    }
}
