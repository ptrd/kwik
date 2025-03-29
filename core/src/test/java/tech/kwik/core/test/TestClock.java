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
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;


public class TestClock extends Clock {

    private Instant instant;
    private ZoneId zone;
    private List<ClockListener> listeners;
    private List<Instant> ticks;

    public TestClock() {
        instant = Instant.EPOCH;  // Debugging is easier when the clock starts at a fixed point in time.
        zone = ZoneOffset.UTC;
        listeners = new ArrayList<>();
        ticks = new ArrayList<>();
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

    private void notifyListeners() {
        listeners.forEach(l -> l.clockAdvanced());
    }

    public void fastForward(int millis) {
        int clockAdvanceInaccuracyNanos = 1;  // when advancing clock, always add some inaccuracy to avoid a scheduled task running exactly at the scheduled time (which isn't realistic and leads to failing tests in combination with Instant.after())
        int remainingTime = millis;
        while (remainingTime > 0 && !ticks.isEmpty()) {
            long nextTick = ticks.get(0).toEpochMilli() - instant.toEpochMilli();
            if (nextTick <= remainingTime) {
                instant = instant.plusMillis(nextTick).plusNanos(clockAdvanceInaccuracyNanos);
                ticks.remove(0);
                remainingTime -= nextTick;
                notifyListeners();
            }
            else {
                instant = instant.plusMillis(remainingTime).plusNanos(clockAdvanceInaccuracyNanos);
                remainingTime = 0;
                notifyListeners();
            }
        }
        if (remainingTime > 0) {
            instant = instant.plusMillis(remainingTime).plusNanos(clockAdvanceInaccuracyNanos);
            notifyListeners();
        }
    }

    public void registerListener(ClockListener listener) {
        listeners.add(listener);
    }

    public void setTick(long delayInMillis) {
        if (delayInMillis <= 0) {
            // In reality, a clock is always advancing; when scheduling something with 0 delay, it is not executed with 0 delay.
            delayInMillis = 1;
        }
        ticks.add(instant.plusMillis(delayInMillis));
        ticks.sort(Instant::compareTo);
    }

    public interface ClockListener {
        void clockAdvanced();
    }
}
