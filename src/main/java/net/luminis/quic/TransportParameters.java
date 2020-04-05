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

import java.net.InetAddress;

public class TransportParameters {

    private byte[] originalConnectionId;
    private long maxIdleTimeout;
    private long initialMaxData;
    private long initialMaxStreamDataBidiLocal;
    private long initialMaxStreamDataBidiRemote;
    private long initialMaxStreamDataUni;
    private long initialMaxStreamsBidi;
    private long initialMaxStreamsUni;
    private int ackDelayExponent;
    private boolean disableMigration;
    private PreferredAddress preferredAddress;
    private int maxAckDelay;
    private int activeConnectionIdLimit;


    public TransportParameters() {
        setDefaults();
    }

    public TransportParameters(int maxIdleTimeoutInSeconds, int initialMaxStreamData, int initialMaxStreamsBidirectional, int initialMaxStreamsUnidirectional) {
        setDefaults();
        this.maxIdleTimeout = maxIdleTimeoutInSeconds * 1000;
        setInitialMaxStreamData(initialMaxStreamData);
        initialMaxData = 10 * initialMaxStreamData;
        initialMaxStreamsBidi = initialMaxStreamsBidirectional;
        initialMaxStreamsUni = initialMaxStreamsUnidirectional;
        ackDelayExponent = 0;
    }

    private void setDefaults() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-18.1
        // "If this value is absent, a default of 25 milliseconds is assumed."
        maxAckDelay = 25;
        // https://tools.ietf.org/html/draft-ietf-quic-transport-25#section-18.2
        // "If this transport parameter is absent, a default of 2 is assumed."
        activeConnectionIdLimit = 2;
    }

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

    public long getMaxIdleTimeout() {
        return maxIdleTimeout;
    }

    public void setMaxIdleTimeout(long idleTimeout) {
        maxIdleTimeout = idleTimeout;
    }

    public long getInitialMaxData() {
        return initialMaxData;
    }

    public void setInitialMaxData(long initialMaxData) {
        this.initialMaxData = initialMaxData;
    }

    public long getInitialMaxStreamDataBidiLocal() {
        return initialMaxStreamDataBidiLocal;
    }

    public void setInitialMaxStreamDataBidiLocal(long initialMaxStreamDataBidiLocal) {
        this.initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal;
    }

    public long getInitialMaxStreamDataBidiRemote() {
        return initialMaxStreamDataBidiRemote;
    }

    public void setInitialMaxStreamDataBidiRemote(long initialMaxStreamDataBidiRemote) {
        this.initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote;
    }

    public long getInitialMaxStreamDataUni() {
        return initialMaxStreamDataUni;
    }

    public void setInitialMaxStreamDataUni(long initialMaxStreamDataUni) {
        this.initialMaxStreamDataUni = initialMaxStreamDataUni;
    }

    public void setInitialMaxStreamData(long maxStreamData) {
        // All stream data values are equal. When changing this, also change the getter in QuicConnection, used by the streams.
        initialMaxStreamDataBidiLocal = maxStreamData;
        initialMaxStreamDataBidiRemote = maxStreamData;
        initialMaxStreamDataUni = maxStreamData;
    }

    public long getInitialMaxStreamsBidi() {
        return initialMaxStreamsBidi;
    }

    public void setInitialMaxStreamsBidi(long initialMaxStreamsBidi) {
        this.initialMaxStreamsBidi = initialMaxStreamsBidi;
    }

    public long getInitialMaxStreamsUni() {
        return initialMaxStreamsUni;
    }

    public void setInitialMaxStreamsUni(long initialMaxStreamsUni) {
        this.initialMaxStreamsUni = initialMaxStreamsUni;
    }

    public void setMaxAckDelay(int maxAckDelay) {
        this.maxAckDelay = maxAckDelay;
    }

    public int getMaxAckDelay() {
        return maxAckDelay;
    }

    public int getActiveConnectionIdLimit() {
        return activeConnectionIdLimit;
    }

    public void setActiveConnectionIdLimit(int activeConnectionIdLimit) {
        this.activeConnectionIdLimit = activeConnectionIdLimit;
    }

    public void setDisableMigration(boolean disableMigration) {
        this.disableMigration = disableMigration;
    }

    public boolean getDisableMigration() {
        return disableMigration;
    }

    @Override
    public String toString() {
        return "\n- max idle timeout\t" + (maxIdleTimeout / 1000) +
                "\n- cids limit\t" + activeConnectionIdLimit +
                "\n- disable migration\t" + disableMigration;
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
