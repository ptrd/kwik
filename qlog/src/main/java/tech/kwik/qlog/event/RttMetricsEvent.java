/*
 * Copyright © 2025 Peter Doornbosch
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
package tech.kwik.qlog.event;

import tech.kwik.qlog.QLogEvent;

import java.time.Instant;

public class RttMetricsEvent extends QLogEvent {

    private final int smoothedRtt;
    private final int rttVar;
    private final int latestRtt;

    public RttMetricsEvent(long connectionHandle, byte[] originalDcid, int smoothedRtt, int rttVar, int latestRtt, Instant eventTime) {
        super(connectionHandle, originalDcid, eventTime);
        this.smoothedRtt = smoothedRtt;
        this.rttVar = rttVar;
        this.latestRtt = latestRtt;
    }

    @Override
    public void accept(QLogEventProcessor processor) {
        processor.process(this);
    }

    public int getSmoothedRtt() {
        return smoothedRtt;
    }

    public int getRttVar() {
        return rttVar;
    }

    public int getLatestRtt() {
        return latestRtt;
    }
}
