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

public class RecoveryMetricsEvent extends QLogEvent {

    final private CongestionControlMetricsEvent controlMetricsEvent;
    final private RttMetricsEvent rttMetricsEvent;

    public RecoveryMetricsEvent(CongestionControlMetricsEvent controlMetricsEvent, RttMetricsEvent rttMetricsEvent) {
        super(controlMetricsEvent.getConnectionHandle(),
                controlMetricsEvent.getCid(),
                last(controlMetricsEvent.getTime(), rttMetricsEvent.getTime()));

        this.controlMetricsEvent = controlMetricsEvent;
        this.rttMetricsEvent = rttMetricsEvent;
    }

    private static Instant last(Instant time1, Instant time2) {
        return time1.isAfter(time2) ? time1 : time2;
    }

    @Override
    public void accept(QLogEventProcessor processor) {
        processor.process(this);
    }

    public int getSmoothedRtt() {
        return rttMetricsEvent.getSmoothedRtt();
    }

    public int getRttVar() {
        return rttMetricsEvent.getRttVar();
    }

    public int getLatestRtt() {
        return rttMetricsEvent.getLatestRtt();
    }

    public long getBytesInFlight() {
        return controlMetricsEvent.getBytesInFlight();
    }

    public long getCongestionWindow() {
        return controlMetricsEvent.getCongestionWindow();
    }
}
