/*
 * Copyright © 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic.send;

public class SendStatistics {

    private final int datagramsSent;
    private final long packetsSent;
    private final long bytesSent;
    private final long lostPackets;
    private final int smoothedRtt;
    private final int rttVar;
    private final int latestRtt;

    public SendStatistics(int datagramsSent, long packetsSent, long bytesSent, long lostPackets, int smoothedRtt, int rttVar, int latestRtt) {
        this.datagramsSent = datagramsSent;
        this.packetsSent = packetsSent;
        this.bytesSent = bytesSent;
        this.lostPackets = lostPackets;
        this.smoothedRtt = smoothedRtt;
        this.rttVar = rttVar;
        this.latestRtt = latestRtt;
    }

    public int datagramsSent() {
        return datagramsSent;
    }

    public long bytesSent() {
        return bytesSent;
    }

    public long lostPackets() {
        return lostPackets;
    }

    public long packetsSent() {
        return packetsSent;
    }

    public int smoothedRtt() {
        return smoothedRtt;
    }

    public int rttVar() {
        return rttVar;
    }

    public int latestRtt() {
        return latestRtt;
    }
}
