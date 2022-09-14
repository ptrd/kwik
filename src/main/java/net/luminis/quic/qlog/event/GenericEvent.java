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

/**
 * QLog QUIC events generic:*
 * See https://www.ietf.org/archive/id/draft-ietf-quic-qlog-main-schema-03.html#name-generic-events
 */
public class GenericEvent extends QLogEvent {

    public enum Type {
        Error,
        Warning,
        Info,
        Debug,
        Verbose
    }

    private final Type type;
    private final String message;

    public GenericEvent(byte[] cid, Instant time, Type type, String message) {
        super(cid, time);
        this.type = type;
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public Type getType() {
        return type;
    }

    @Override
    public void accept(QLogEventProcessor processor) {
        processor.process(this);
    }
}
