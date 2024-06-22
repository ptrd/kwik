/*
 * Copyright © 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.core;

import net.luminis.quic.concurrent.DaemonThreadFactory;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.IntSupplier;

public class IdleTimer {

    private final Clock clock;
    private final ScheduledExecutorService timer;
    private final int timerResolution;
    private volatile long timeout;
    private final QuicConnectionImpl connection;
    private final Logger log;
    private volatile IntSupplier ptoSupplier;
    private volatile Instant lastAction;
    private volatile boolean enabled;
    private ScheduledFuture<?> timerTask;


    public IdleTimer(QuicConnectionImpl connection, Logger logger) {
        this(connection, logger, 1000);
    }

    public IdleTimer(QuicConnectionImpl connection, Logger logger, int timerResolution) {
        this(Clock.systemUTC(), connection, logger, timerResolution);
    }

    public IdleTimer(Clock clock, QuicConnectionImpl connection, Logger logger, int timerResolution) {
        this.clock = clock;
        this.connection = connection;
        this.ptoSupplier = () -> 0;
        this.log = logger;
        this.timerResolution = timerResolution;

        timer = Executors.newScheduledThreadPool(1, new DaemonThreadFactory("idle-timer"));
        lastAction = clock.instant();
    }

    void setIdleTimeout(long idleTimeoutInMillis) {
        timeout = idleTimeoutInMillis;
        if (! enabled) {
            enabled = true;
        }
        else {
            timerTask.cancel(true);
        }
        timerTask = timer.scheduleAtFixedRate(() -> checkIdle(), timerResolution, timerResolution, TimeUnit.MILLISECONDS);
    }

    long getIdleTimeout() {
        return timeout;
    }

    boolean isEnabled() {
        return enabled;
    }

    public void setPtoSupplier(IntSupplier ptoSupplier) {
        this.ptoSupplier = ptoSupplier;
    }

    private void checkIdle() {
        if (enabled) {
            Instant now = clock.instant();
            if (lastAction.plusMillis(timeout).isBefore(now)) {
                int currentPto = ptoSupplier.getAsInt();
                // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
                // To avoid excessively small idle timeout periods, endpoints MUST increase the idle timeout period
                // to be at least three times the current Probe Timeout (PTO)
                if (lastAction.plusMillis(3L * currentPto).isBefore(now)) {
                    timer.shutdown();
                    connection.silentlyCloseConnection(timeout + currentPto);
                }
            }}
    }

    public void packetProcessed() {
        if (enabled) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
            // "An endpoint restarts its idle timer when a packet from its peer is received and processed successfully."
            lastAction = clock.instant();
        }
    }

    public void packetSent(QuicPacket packet, Instant sendTime) {
        if (enabled) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
            // "An endpoint also restarts its idle timer when sending an ack-eliciting packet if no other ack-eliciting
            //  packets have been sent since last receiving and processing a packet. "
            if (packet.isAckEliciting()) {
                lastAction = sendTime;
            }
        }
    }

    public void shutdown() {
        if (enabled) {
            timer.shutdown();
        }
    }
}

