/*
 * Copyright © 2022 Peter Doornbosch
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
package net.luminis.quic.qlog.event;

import net.luminis.quic.qlog.QLogEvent;

import java.time.Instant;

public class RttMetricsEvent extends QLogEvent {

    private final int minRtt;
    private final int smoothedRtt;
    private final int latestRtt;
    private final int rttVariance;

    public RttMetricsEvent(byte[] cid, int minRtt, int smoothedRtt, int latestRtt, int rttVariance, Instant eventTime) {
        super(cid, eventTime);
        this.minRtt = minRtt;
        this.smoothedRtt = smoothedRtt;
        this.latestRtt = latestRtt;
        this.rttVariance = rttVariance;
    }

    public int getMinRtt() {
        return minRtt;
    }

    public int getSmoothedRtt() {
        return smoothedRtt;
    }

    public int getLatestRtt() {
        return latestRtt;
    }

    public int getRttVariance() {
        return rttVariance;
    }

    @Override
    public void accept(QLogEventProcessor processor) {
        processor.process(this);
    }
}
