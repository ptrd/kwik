/*
 * Copyright © 2020, 2021, 2022 Peter Doornbosch
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
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class QuicSessionTicketTest {

    @Test
    void serializeAndDeserializeReturnsSameResult() throws Exception {
        TransportParameters tp = new TransportParameters();
        long maxIdleTime = 38;
        tp.setMaxIdleTimeout(maxIdleTime);
        int maxPacketSize = 1215;
        tp.setMaxUdpPayloadSize(maxPacketSize);
        long maxData = 123456789;
        tp.setInitialMaxData(maxData);
        long maxDataBidiLocal = 58374;
        tp.setInitialMaxStreamDataBidiLocal(maxDataBidiLocal);
        long maxDataBidiRemote = 859234;
        tp.setInitialMaxStreamDataBidiRemote(maxDataBidiRemote);
        long maxDataUni = 38402;
        tp.setInitialMaxStreamDataUni(maxDataUni);
        long maxStreamsBidi = 38;
        tp.setInitialMaxStreamsBidi(maxStreamsBidi);
        long maxStreamsUni = 513;
        tp.setInitialMaxStreamsUni(maxStreamsUni);
        int maxAckDelay = 284;
        tp.setMaxAckDelay(maxAckDelay);
        boolean disableMigration = true;
        tp.setDisableMigration(disableMigration);
        NewSessionTicket tlsTicket = mock(NewSessionTicket.class);
        when(tlsTicket.serialize()).thenReturn(new byte[16]);   // Exact size doesn't matter
        QuicSessionTicket quicSessionTicket = new QuicSessionTicket(tlsTicket, tp);

        byte[] serializedData = quicSessionTicket.serialize();

        QuicSessionTicket restoredTicket = QuicSessionTicket.deserialize(serializedData);
        assertThat(restoredTicket.getMaxIdleTimeout()).isEqualTo(maxIdleTime);
        assertThat(restoredTicket.getMaxPacketSize()).isEqualTo(maxPacketSize);
        assertThat(restoredTicket.getInitialMaxData()).isEqualTo(maxData);
        assertThat(restoredTicket.getInitialMaxStreamDataBidiLocal()).isEqualTo(maxDataBidiLocal);
        assertThat(restoredTicket.getInitialMaxStreamDataBidiRemote()).isEqualTo(maxDataBidiRemote);
        assertThat(restoredTicket.getInitialMaxStreamDataUni()).isEqualTo(maxDataUni);
        assertThat(restoredTicket.getInitialMaxStreamsBidi()).isEqualTo(maxStreamsBidi);
        assertThat(restoredTicket.getInitialMaxStreamsUni()).isEqualTo(maxStreamsUni);
        assertThat(restoredTicket.getMaxAckDelay()).isEqualTo(maxAckDelay);
        assertThat(restoredTicket.getDisableActiveMigration()).isEqualTo(disableMigration);
    }

    @Test
    void copyToReturnsSameResult() throws Exception {
        TransportParameters tp = new TransportParameters();
        long maxIdleTime = 38;
        tp.setMaxIdleTimeout(maxIdleTime);
        int maxPacketSize = 1215;
        tp.setMaxUdpPayloadSize(maxPacketSize);
        long maxData = 123456789;
        tp.setInitialMaxData(maxData);
        long maxDataBidiLocal = 58374;
        tp.setInitialMaxStreamDataBidiLocal(maxDataBidiLocal);
        long maxDataBidiRemote = 859234;
        tp.setInitialMaxStreamDataBidiRemote(maxDataBidiRemote);
        long maxDataUni = 38402;
        tp.setInitialMaxStreamDataUni(maxDataUni);
        long maxStreamsBidi = 38;
        tp.setInitialMaxStreamsBidi(maxStreamsBidi);
        long maxStreamsUni = 513;
        tp.setInitialMaxStreamsUni(maxStreamsUni);
        int maxAckDelay = 284;
        tp.setMaxAckDelay(maxAckDelay);
        boolean disableMigration = true;
        tp.setDisableMigration(disableMigration);
        NewSessionTicket tlsTicket = mock(NewSessionTicket.class);
        QuicSessionTicket quicSessionTicket = new QuicSessionTicket(tlsTicket, tp);

        TransportParameters copiedTransportParameters = new TransportParameters();
        quicSessionTicket.copyTo(copiedTransportParameters);

        assertThat(copiedTransportParameters.getMaxIdleTimeout()).isEqualTo(maxIdleTime);
        assertThat(copiedTransportParameters.getMaxUdpPayloadSize()).isEqualTo(maxPacketSize);
        assertThat(copiedTransportParameters.getInitialMaxData()).isEqualTo(maxData);
        assertThat(copiedTransportParameters.getInitialMaxStreamDataBidiLocal()).isEqualTo(maxDataBidiLocal);
        assertThat(copiedTransportParameters.getInitialMaxStreamDataBidiRemote()).isEqualTo(maxDataBidiRemote);
        assertThat(copiedTransportParameters.getInitialMaxStreamDataUni()).isEqualTo(maxDataUni);
        assertThat(copiedTransportParameters.getInitialMaxStreamsBidi()).isEqualTo(maxStreamsBidi);
        assertThat(copiedTransportParameters.getInitialMaxStreamsUni()).isEqualTo(maxStreamsUni);
        assertThat(copiedTransportParameters.getMaxAckDelay()).isEqualTo(maxAckDelay);
        assertThat(copiedTransportParameters.getDisableMigration()).isEqualTo(disableMigration);
    }

}
