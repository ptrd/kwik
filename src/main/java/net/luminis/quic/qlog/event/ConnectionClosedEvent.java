/*
 * Copyright © 2021, 2022, 2023 Peter Doornbosch
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

public class ConnectionClosedEvent extends QLogEvent {

    private final Trigger trigger;
    private final Long errorCode;
    private final String errorReason;

    public enum Trigger {
        idleTimeout("idle_timeout"),
        immediateClose("error");

        private final String qlogFormat;

        Trigger(String qlogFormat) {
            this.qlogFormat = qlogFormat;
        }

        public String qlogFormat() {
            return qlogFormat;
        }
    }

    public ConnectionClosedEvent(byte[] cid, Instant time, Trigger trigger) {
        super(cid, time);
        this.trigger = trigger;
        errorCode = null;
        errorReason = null;
    }

    public ConnectionClosedEvent(byte[] cid, Instant time, Trigger trigger, long errorCode, String errorReason) {
        super(cid, time);
        this.trigger = trigger;
        this.errorCode = errorCode;
        this.errorReason = errorReason;
    }

    @Override
    public void accept(QLogEventProcessor processor) {
        processor.process(this);
    }

    public Trigger getTrigger() {
        return trigger;
    }

    public Long getErrorCode() {
        return errorCode;
    }

    public String getErrorReason() {
        return errorReason;
    }
}
