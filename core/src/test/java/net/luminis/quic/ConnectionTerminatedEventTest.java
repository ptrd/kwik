/*
 * Copyright © 2024, 2025 Peter Doornbosch
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

import tech.kwik.agent15.TlsConstants;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.mock;

class ConnectionTerminatedEventTest {

    @Test
    void testErrorDescriptionForFlowControlError() {
        // Given
        var event = new ConnectionTerminatedEvent(mock(QuicConnection.class), ConnectionTerminatedEvent.CloseReason.ImmediateClose, true, (long) QuicConstants.TransportErrorCode.FLOW_CONTROL_ERROR.value, null);

        // When
        var description = event.errorDescription();

        // Then
        assertThat(description).contains("FLOW_CONTROL_ERROR");
    }

    @Test
    void testErrorDescriptionForTlsNoApplicationProtocolAlert() {
        // Given
        var event = new ConnectionTerminatedEvent(mock(QuicConnection.class),
                ConnectionTerminatedEvent.CloseReason.ImmediateClose,
                true,
                (long) QuicConstants.TransportErrorCode.CRYPTO_ERROR.value + TlsConstants.AlertDescription.no_application_protocol.value,
                null);

        // When
        var description = event.errorDescription();

        // Then
        assertThat(description).contains("no_application_protocol");
    }

    @Test
    void testErrorDescriptionForApplicationError() {
        // Given
        var event = new ConnectionTerminatedEvent(mock(QuicConnection.class),
                ConnectionTerminatedEvent.CloseReason.ImmediateClose,
                true,
                null,
                0x0107L);  // example from HTTP/3: H3_EXCESSIVE_LOAD

        // When
        var description = event.errorDescription();

        // Then
        assertThat(description)
                .contains("Application error")
                .contains("" + 0x0107);
    }
}