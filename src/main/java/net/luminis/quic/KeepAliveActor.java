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

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;


import static java.time.temporal.ChronoUnit.SECONDS;
import static net.luminis.quic.EncryptionLevel.App;


public class KeepAliveActor {

    private final Version quicVersion;
    private final int keepAliveTime;
    private final int peerIdleTimeout;
    private final QuicConnection connection;
    private final Instant started;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private final int pingInterval;
    private volatile ScheduledFuture<?> scheduledTask;

    public KeepAliveActor(Version quicVersion, int keepAliveTime, int peerIdleTimeout, QuicConnection connection) {
        this.quicVersion = quicVersion;
        this.keepAliveTime = keepAliveTime;
        this.peerIdleTimeout = quicVersion.before(Version.IETF_draft_19)? peerIdleTimeout: peerIdleTimeout * 1000;
        this.connection = connection;
        started = Instant.now();
        pingInterval = peerIdleTimeout / 2;

        scheduleNextPing();
    }

    private void ping() {
        QuicPacket packet = connection.createPacket(App, new PingFrame(quicVersion));
        packet.frames.add(new Padding(20));  // TODO: find out minimum packet size
        connection.send(packet, "ping");

        scheduleNextPing();
    }

    public void notifyPacketSent() {
        scheduledTask.cancel(false);
        scheduleNextPing();
    }

    private void scheduleNextPing() {
        Instant now = Instant.now();
        if (Duration.between(started, now).compareTo(Duration.of(keepAliveTime - pingInterval, SECONDS)) < 0) {
            scheduledTask = scheduler.schedule(() -> ping(), pingInterval, java.util.concurrent.TimeUnit.SECONDS);
        }
    }

    public void shutdown() {
        scheduler.shutdown();
    }
}
