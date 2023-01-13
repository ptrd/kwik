/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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
package net.luminis.quic;

import net.luminis.quic.frame.PingFrame;
import net.luminis.quic.send.Sender;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;

import static java.time.temporal.ChronoUnit.SECONDS;
import static net.luminis.quic.EncryptionLevel.App;


public class KeepAliveActor {

    private Clock clock;
    private final VersionHolder quicVersion;
    private final int keepAliveTime;
    private final Sender sender;
    private final Instant started;
    private final ScheduledExecutorService scheduler;
    private final int pingInterval;
    private volatile ScheduledFuture<?> scheduledTask;

    /**
     * @param quicVersion
     * @param keepAliveTime       the time the connection should be kept alive in seconds
     * @param peerIdleTimeout     the idle timeout of the peer, in milliseconds
     * @param sender
     */
    public KeepAliveActor(VersionHolder quicVersion, int keepAliveTime, int peerIdleTimeout, Sender sender) {
        this(Clock.systemUTC(), quicVersion, keepAliveTime, peerIdleTimeout, sender, Executors.newScheduledThreadPool(1));
    }

    KeepAliveActor(Clock clock, VersionHolder quicVersion, int keepAliveTime, int peerIdleTimeout, Sender sender, ScheduledExecutorService scheduler) {
        this.clock = clock;
        this.quicVersion = quicVersion;
        this.keepAliveTime = keepAliveTime;
        this.sender = sender;
        this.scheduler = scheduler;

        started = clock.instant();
        pingInterval = peerIdleTimeout / 1000 / 2;

        scheduleNextPing();
    }

    private void ping() {
        sender.send(new PingFrame(quicVersion.getVersion()), App);
        sender.flush();

        scheduleNextPing();
    }

    private void scheduleNextPing() {
        Instant now = clock.instant();
        if (Duration.between(started, now).compareTo(Duration.of(keepAliveTime - pingInterval, SECONDS)) < 0) {
            scheduledTask = scheduler.schedule(() -> ping(), pingInterval, java.util.concurrent.TimeUnit.SECONDS);
        }
    }

    public void shutdown() {
        scheduler.shutdown();
    }
}
