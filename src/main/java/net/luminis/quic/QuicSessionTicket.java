/*
 * Copyright © 2019 Peter Doornbosch
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

import net.luminis.tls.NewSessionTicket;

import java.nio.ByteBuffer;
import java.util.Date;

/**
 * Extension of TLS NewSessionTicket to hold (relevant) QUIC transport parameters too, in order to being able to
 * send 0-RTT packets.
 *
 * https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-7.3.1
 * "Both endpoints store the value of the server transport parameters
 *    from a connection and apply them to any 0-RTT packets that are sent
 *    in subsequent connections to that peer, except for transport
 *    parameters that are explicitly excluded."
 * "A client MUST NOT use remembered values for the following parameters:
 *    original_connection_id, preferred_address, stateless_reset_token,
 *    ack_delay_exponent and active_connection_id_limit."
 */
public class QuicSessionTicket extends NewSessionTicket {

    private static final int SERIALIZED_SIZE = 7 * 8 + 2 * 4 + 1;

    private NewSessionTicket wrappedTicket;
    private long maxIdleTimeout;
    private int maxPacketSize;
    private long initialMaxData;
    private long initialMaxStreamDataBidiLocal;
    private long initialMaxStreamDataBidiRemote;
    private long initialMaxStreamDataUni;
    private long initialMaxStreamsBidi;
    private long initialMaxStreamsUni;
    private int maxAckDelay;
    private boolean disableActiveMigration;


    QuicSessionTicket(NewSessionTicket tlsTicket, TransportParameters serverParameters) {
        wrappedTicket = tlsTicket;
        maxIdleTimeout = serverParameters.getMaxIdleTimeout();
        maxPacketSize = serverParameters.getMaxUdpPayloadSize();
        initialMaxData = serverParameters.getInitialMaxData();
        initialMaxStreamDataBidiLocal = serverParameters.getInitialMaxStreamDataBidiLocal();
        initialMaxStreamDataBidiRemote = serverParameters.getInitialMaxStreamDataBidiRemote();
        initialMaxStreamDataUni = serverParameters.getInitialMaxStreamDataUni();
        initialMaxStreamsBidi = serverParameters.getInitialMaxStreamsBidi();
        initialMaxStreamsUni = serverParameters.getInitialMaxStreamsUni();
        maxAckDelay = serverParameters.getMaxAckDelay();
        disableActiveMigration = serverParameters.getDisableMigration();
    }

    public QuicSessionTicket(byte[] data) {
        super(data);
        ByteBuffer buffer = ByteBuffer.wrap(data, data.length - SERIALIZED_SIZE, SERIALIZED_SIZE);
        wrappedTicket = this;
        maxIdleTimeout = buffer.getLong();
        maxPacketSize = buffer.getInt();
        initialMaxData = buffer.getLong();
        initialMaxStreamDataBidiLocal = buffer.getLong();
        initialMaxStreamDataBidiRemote = buffer.getLong();
        initialMaxStreamDataUni = buffer.getLong();
        initialMaxStreamsBidi = buffer.getLong();
        initialMaxStreamsUni = buffer.getLong();
        maxAckDelay = buffer.getInt();
        disableActiveMigration = buffer.get() == 1;
    }

    public byte[] serialize() {
        byte[] serializedTicket;
        if (wrappedTicket != this) {
            serializedTicket = wrappedTicket.serialize();
        }
        else {
            serializedTicket = super.serialize();
        }
        ByteBuffer buffer = ByteBuffer.allocate(serializedTicket.length + SERIALIZED_SIZE);
        buffer.put(serializedTicket);
        buffer.putLong(maxIdleTimeout);
        buffer.putInt(maxPacketSize);
        buffer.putLong(initialMaxData);
        buffer.putLong(initialMaxStreamDataBidiLocal);
        buffer.putLong(initialMaxStreamDataBidiRemote);
        buffer.putLong(initialMaxStreamDataUni);
        buffer.putLong(initialMaxStreamsBidi);
        buffer.putLong(initialMaxStreamsUni);
        buffer.putInt(maxAckDelay);
        buffer.put((byte) (disableActiveMigration? 1: 0));
        return buffer.array();
    }

    @Override
    public byte[] getPSK() {
        if (wrappedTicket != this) {
            return wrappedTicket.getPSK();
        }
        else {
            return super.getPSK();
        }
    }

    @Override
    public Date getTicketCreationDate() {
        if (wrappedTicket != this) {
            return wrappedTicket.getTicketCreationDate();
        }
        else {
            return super.getTicketCreationDate();
        }
    }

    @Override
    public long getTicketAgeAdd() {
        if (wrappedTicket != this) {
            return wrappedTicket.getTicketAgeAdd();
        }
        else {
            return super.getTicketAgeAdd();
        }
    }

    @Override
    public byte[] getSessionTicketIdentity() {
        if (wrappedTicket != this) {
            return wrappedTicket.getSessionTicketIdentity();
        }
        else {
            return super.getSessionTicketIdentity();
        }
    }

    public void copyTo(TransportParameters tp) {
        tp.setMaxIdleTimeout(maxIdleTimeout);
        tp.setMaxUdpPayloadSize(maxPacketSize);
        tp.setInitialMaxData(initialMaxData);
        tp.setInitialMaxStreamDataBidiLocal(initialMaxStreamDataBidiLocal);
        tp.setInitialMaxStreamDataBidiRemote(initialMaxStreamDataBidiRemote);
        tp.setInitialMaxStreamDataUni(initialMaxStreamDataUni);
        tp.setInitialMaxStreamsBidi(initialMaxStreamsBidi);
        tp.setInitialMaxStreamsUni(initialMaxStreamsUni);
        tp.setMaxAckDelay(maxAckDelay);
        tp.setDisableMigration(disableActiveMigration);
    }

    public static QuicSessionTicket deserialize(byte[] data) {
        return new QuicSessionTicket(data);
    }

    public long getMaxIdleTimeout() {
        return maxIdleTimeout;
    }

    public int getMaxPacketSize() {
        return maxPacketSize;
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

    public boolean getDisableActiveMigration() {
        return disableActiveMigration;
    }
}

