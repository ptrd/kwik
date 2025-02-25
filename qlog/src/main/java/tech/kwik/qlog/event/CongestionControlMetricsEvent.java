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
package tech.kwik.qlog.event;

import tech.kwik.qlog.QLogEvent;

import java.time.Instant;

public class CongestionControlMetricsEvent extends QLogEvent {

    private final long congestionWindow;
    private final long bytesInFlight;

    public CongestionControlMetricsEvent(long connectionHandle, byte[] originalDcid, long congestionWindow, long bytesInFlight, Instant eventTime) {
        super(connectionHandle, originalDcid, eventTime);
        this.congestionWindow = congestionWindow;
        this.bytesInFlight = bytesInFlight;
    }

    @Override
    public void accept(QLogEventProcessor processor) {
        processor.process(this);
    }

    public long getCongestionWindow() {
        return congestionWindow;
    }

    public long getBytesInFlight() {
        return bytesInFlight;
    }
}
