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

import net.luminis.tls.NewSessionTicket;

import java.nio.ByteBuffer;

/**
 * Extension of TLS NewSessionTicket to hold (relevant) QUIC transport parameters too, in order to being able to
 * send 0-RTT packets.
 *
 * https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-7.3.1
 * "A client that attempts to send 0-RTT data MUST remember all other
 *    transport parameters used by the server."
 */
public class QuicSessionTicket extends NewSessionTicket {

    private NewSessionTicket wrappedTicket;
    private long idleTimeoutInSeconds;
    private long initialMaxData;
    private long initialMaxStreamDataBidiLocal;
    private long initialMaxStreamDataBidiRemote;
    private long initialMaxStreamDataUni;
    private long initialMaxStreamsBidi;
    private long initialMaxStreamsUni;
    private int maxAckDelay;
    // TODO: this list is not complete (as is the TransportParameters class)

    QuicSessionTicket(NewSessionTicket tlsTicket, TransportParameters serverParameters) {
        wrappedTicket = tlsTicket;
        idleTimeoutInSeconds = serverParameters.getMaxIdleTimeout();
        initialMaxData = serverParameters.getInitialMaxData();
        initialMaxStreamDataBidiLocal = serverParameters.getInitialMaxStreamDataBidiLocal();
        initialMaxStreamDataBidiRemote = serverParameters.getInitialMaxStreamDataBidiRemote();
        initialMaxStreamDataUni = serverParameters.getInitialMaxStreamDataUni();
        initialMaxStreamsBidi = serverParameters.getInitialMaxStreamsBidi();
        initialMaxStreamsUni = serverParameters.getInitialMaxStreamsUni();
        maxAckDelay = serverParameters.getMaxAckDelay();
    }

    public QuicSessionTicket(byte[] data) {
        super(data);
        ByteBuffer buffer = ByteBuffer.wrap(data, data.length - 8 * 8, 8 * 8);
        wrappedTicket = this;
        idleTimeoutInSeconds = buffer.getLong();
        initialMaxData = buffer.getLong();
        initialMaxStreamDataBidiLocal = buffer.getLong();
        initialMaxStreamDataBidiRemote = buffer.getLong();
        initialMaxStreamDataUni = buffer.getLong();
        initialMaxStreamsBidi = buffer.getLong();
        initialMaxStreamsUni = buffer.getLong();
        maxAckDelay = (int) buffer.getLong();
    }

    public byte[] serialize() {
        byte[] serializedTicket = wrappedTicket.serialize();
        ByteBuffer buffer = ByteBuffer.allocate(serializedTicket.length + 8 * 8);
        buffer.put(serializedTicket);
        buffer.putLong(idleTimeoutInSeconds);
        buffer.putLong(initialMaxData);
        buffer.putLong(initialMaxStreamDataBidiLocal);
        buffer.putLong(initialMaxStreamDataBidiRemote);
        buffer.putLong(initialMaxStreamDataUni);
        buffer.putLong(initialMaxStreamsBidi);
        buffer.putLong(initialMaxStreamsUni);
        buffer.putLong(maxAckDelay);
        return buffer.array();
    }

    public static QuicSessionTicket deserialize(byte[] data) {
        return new QuicSessionTicket(data);
    }

    public long getIdleTimeoutInSeconds() {
        return idleTimeoutInSeconds;
    }

    public long getInitialMaxData() {
        return initialMaxData;
    }

    public long getInitialMaxStreamDataBidiLocal() {
        return initialMaxStreamDataBidiLocal;
    }

    public long getInitialMaxStreamDataBidiRemote() {
        return initialMaxStreamDataBidiRemote;
    }

    public long getInitialMaxStreamDataUni() {
        return initialMaxStreamDataUni;
    }

    public long getInitialMaxStreamsBidi() {
        return initialMaxStreamsBidi;
    }

    public long getInitialMaxStreamsUni() {
        return initialMaxStreamsUni;
    }

    public int getMaxAckDelay() {
        return maxAckDelay;
    }
}

