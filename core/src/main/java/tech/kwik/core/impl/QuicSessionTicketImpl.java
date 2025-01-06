/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.impl;

import tech.kwik.core.QuicSessionTicket;
import tech.kwik.agent15.NewSessionTicket;
import tech.kwik.agent15.TlsConstants;

import java.nio.ByteBuffer;

/**
 * Extension of TLS NewSessionTicket to hold (relevant) QUIC transport parameters too, in order to be able to
 * send 0-RTT packets.
 *
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-values-of-transport-paramet
 * "To enable 0-RTT, endpoints store the values of the server transport parameters with any session tickets it receives
 *  on the connection. (...) The values of stored transport parameters are used when attempting 0-RTT using the session
 *  tickets."
 * "A client MUST NOT use remembered values for the following parameters: ack_delay_exponent, max_ack_delay,
 *  initial_source_connection_id, original_destination_connection_id, preferred_address, retry_source_connection_id,
 *  and stateless_reset_token."
 *  "A client that attempts to send 0-RTT data MUST remember all other transport parameters used by the server that
 *  it is able to process."
 */
public class QuicSessionTicketImpl implements QuicSessionTicket {

    private static final int SERIALIZED_SIZE = 7 * 8 + 2 * 4 + 1 + 4;

    private NewSessionTicket tlsTicket;
    private long maxIdleTimeout;
    private int maxPacketSize;
    private long initialMaxData;
    private long initialMaxStreamDataBidiLocal;
    private long initialMaxStreamDataBidiRemote;
    private long initialMaxStreamDataUni;
    private long initialMaxStreamsBidi;
    private long initialMaxStreamsUni;
    private boolean disableActiveMigration;
    private int activeConnectionIdLimit;


    QuicSessionTicketImpl(NewSessionTicket tlsTicket, TransportParameters serverParameters) {
        this.tlsTicket = tlsTicket;

        maxIdleTimeout = serverParameters.getMaxIdleTimeout();
        maxPacketSize = serverParameters.getMaxUdpPayloadSize();
        initialMaxData = serverParameters.getInitialMaxData();
        initialMaxStreamDataBidiLocal = serverParameters.getInitialMaxStreamDataBidiLocal();
        initialMaxStreamDataBidiRemote = serverParameters.getInitialMaxStreamDataBidiRemote();
        initialMaxStreamDataUni = serverParameters.getInitialMaxStreamDataUni();
        initialMaxStreamsBidi = serverParameters.getInitialMaxStreamsBidi();
        initialMaxStreamsUni = serverParameters.getInitialMaxStreamsUni();
        disableActiveMigration = serverParameters.getDisableMigration();
        activeConnectionIdLimit = serverParameters.getActiveConnectionIdLimit();
    }

    private QuicSessionTicketImpl(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        int tlsTicketSize = buffer.getInt();
        byte[] tlsTicketData = new byte[tlsTicketSize];
        buffer.get(tlsTicketData);
        tlsTicket = NewSessionTicket.deserialize(tlsTicketData);
        buffer.position(4 + tlsTicketSize);
        maxIdleTimeout = buffer.getLong();
        maxPacketSize = buffer.getInt();
        initialMaxData = buffer.getLong();
        initialMaxStreamDataBidiLocal = buffer.getLong();
        initialMaxStreamDataBidiRemote = buffer.getLong();
        initialMaxStreamDataUni = buffer.getLong();
        initialMaxStreamsBidi = buffer.getLong();
        initialMaxStreamsUni = buffer.getLong();
        disableActiveMigration = buffer.get() == 1;
        activeConnectionIdLimit = buffer.getInt();
    }

    public byte[] serialize() {
        byte[] serializedTicket = tlsTicket.serialize();
        ByteBuffer buffer = ByteBuffer.allocate(4 + serializedTicket.length + SERIALIZED_SIZE);
        buffer.putInt(serializedTicket.length);
        buffer.put(serializedTicket);
        buffer.putLong(maxIdleTimeout);
        buffer.putInt(maxPacketSize);
        buffer.putLong(initialMaxData);
        buffer.putLong(initialMaxStreamDataBidiLocal);
        buffer.putLong(initialMaxStreamDataBidiRemote);
        buffer.putLong(initialMaxStreamDataUni);
        buffer.putLong(initialMaxStreamsBidi);
        buffer.putLong(initialMaxStreamsUni);
        buffer.put((byte) (disableActiveMigration? 1: 0));
        buffer.putInt(activeConnectionIdLimit);
        return buffer.array();
    }

    public NewSessionTicket getTlsSessionTicket() {
        return tlsTicket;
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
        tp.setDisableMigration(disableActiveMigration);
        tp.setActiveConnectionIdLimit(activeConnectionIdLimit);
    }

    public static QuicSessionTicketImpl deserialize(byte[] data) {
        return new QuicSessionTicketImpl(data);
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

    public boolean getDisableActiveMigration() {
        return disableActiveMigration;
    }

    public int getActiveConnectionIdLimit() {
        return activeConnectionIdLimit;
    }

    public TlsConstants.CipherSuite getCipher() {
        return tlsTicket.getCipher();
    }
}

