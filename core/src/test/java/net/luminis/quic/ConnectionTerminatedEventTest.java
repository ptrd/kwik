package net.luminis.quic;

import net.luminis.tls.TlsConstants;
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