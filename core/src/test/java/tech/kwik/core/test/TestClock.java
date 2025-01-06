/*
 * Copyright © 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.TemporalAmount;
import java.util.ArrayList;
import java.util.List;


public class TestClock extends Clock {

    private Instant instant;
    private ZoneId zone;
    private List<ClockListener> listeners;

    public TestClock() {
        instant = Instant.now();
        zone = ZoneOffset.UTC;
        listeners = new ArrayList<>();
    }

    public TestClock(Instant instant, ZoneId zone) {
        this.instant = instant;
        this.zone = zone;
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return new TestClock(instant, zone);
    }

    @Override
    public Instant instant() {
        return instant;
    }

    public void fastForward(TemporalAmount temporalAmount) {
        instant = instant.plus(temporalAmount);
        notifyListeners();
    }

    private void notifyListeners() {
        listeners.forEach(l -> l.clockAdvanced());
    }

    public void fastForward(int millis) {
        fastForward(Duration.ofMillis(millis));
    }

    public void registerListener(ClockListener listener) {
        listeners.add(listener);
    }

    public interface ClockListener {
        void clockAdvanced();
    }
}
