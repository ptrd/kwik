/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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

import tech.kwik.agent15.NewSessionTicket;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.handshake.NewSessionTicketMessage;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class QuicSessionTicketImplTest {

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
        boolean disableMigration = true;
        tp.setDisableMigration(disableMigration);
        int activeConnectionIdLimit = 7;
        tp.setActiveConnectionIdLimit(activeConnectionIdLimit);
        NewSessionTicket tlsTicket = new NewSessionTicket(new byte[32], new NewSessionTicketMessage(1024, 1024, new byte[8], new byte[32]), TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384);
        byte[] serializedTlsTicket = new byte[36];  // Exact size doesn't matter that much, as long as deserialize succeeds
        // And to make the deserialize succeed, the cipher must be a valid value, e.g. 0x13 0x01
        serializedTlsTicket[28] = 0x13;
        serializedTlsTicket[29] = 0x01;
        QuicSessionTicketImpl quicSessionTicket = new QuicSessionTicketImpl(tlsTicket, tp);

        byte[] serializedData = quicSessionTicket.serialize();

        QuicSessionTicketImpl restoredTicket = QuicSessionTicketImpl.deserialize(serializedData);
        assertThat(restoredTicket.getMaxIdleTimeout()).isEqualTo(maxIdleTime);
        assertThat(restoredTicket.getMaxPacketSize()).isEqualTo(maxPacketSize);
        assertThat(restoredTicket.getInitialMaxData()).isEqualTo(maxData);
        assertThat(restoredTicket.getInitialMaxStreamDataBidiLocal()).isEqualTo(maxDataBidiLocal);
        assertThat(restoredTicket.getInitialMaxStreamDataBidiRemote()).isEqualTo(maxDataBidiRemote);
        assertThat(restoredTicket.getInitialMaxStreamDataUni()).isEqualTo(maxDataUni);
        assertThat(restoredTicket.getInitialMaxStreamsBidi()).isEqualTo(maxStreamsBidi);
        assertThat(restoredTicket.getInitialMaxStreamsUni()).isEqualTo(maxStreamsUni);
        assertThat(restoredTicket.getDisableActiveMigration()).isEqualTo(disableMigration);
        assertThat(restoredTicket.getActiveConnectionIdLimit()).isEqualTo(activeConnectionIdLimit);
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
        boolean disableMigration = true;
        tp.setDisableMigration(disableMigration);
        int activeConnectionIdLimit = 5;
        tp.setActiveConnectionIdLimit(activeConnectionIdLimit);
        NewSessionTicket tlsTicket = mock(NewSessionTicket.class);
        QuicSessionTicketImpl quicSessionTicket = new QuicSessionTicketImpl(tlsTicket, tp);

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
        assertThat(copiedTransportParameters.getDisableMigration()).isEqualTo(disableMigration);
        assertThat(copiedTransportParameters.getActiveConnectionIdLimit()).isEqualTo(activeConnectionIdLimit);
    }

    @Test
    void ticketShouldContainCipher() {
        // Given
        NewSessionTicket tlsSessionTicket = new NewSessionTicket(new byte[32], new NewSessionTicketMessage(), TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384);
        TransportParameters peerTransportParams = new TransportParameters();

        // When
        QuicSessionTicketImpl quicSessionTicket = new QuicSessionTicketImpl(tlsSessionTicket, peerTransportParams);

        // Then
        assertThat(quicSessionTicket.getCipher()).isEqualTo(TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384);
    }

    @Test
    void ticketToStringShouldNotThrow() {
        // Given
        NewSessionTicket tlsSessionTicket = new NewSessionTicket(new byte[32], new NewSessionTicketMessage(), TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384);
        TransportParameters peerTransportParams = new TransportParameters();

        // When
        QuicSessionTicketImpl quicSessionTicket = new QuicSessionTicketImpl(tlsSessionTicket, peerTransportParams);

        // Then
        assertThat(quicSessionTicket.toString()).isNotNull();
    }
}
