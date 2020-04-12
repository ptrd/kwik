/*
 * Copyright © 2020 Peter Doornbosch
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
package net.luminis.quic.stream;

import net.luminis.quic.QuicConnectionImpl;
import net.luminis.quic.Version;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.NullLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.internal.util.reflection.FieldSetter;

import java.io.IOException;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class EarlyDataStreamTest {

    private EarlyDataStream stream;
    private QuicConnectionImpl connection;
    private Logger logger;

    @BeforeEach
    void initObjectUnderTest() {
        connection = mock(QuicConnectionImpl.class);
        when(connection.getMaxPacketSize()).thenReturn(1232);
        when(connection.getMaxShortHeaderPacketOverhead()).thenReturn(29);
        int maxData = 5000;
        FlowControl flowController = new FlowControl(maxData, maxData, maxData, maxData);
        logger = new NullLogger();
        stream = new EarlyDataStream(Version.getDefault(), 0, connection, flowController, logger);
    }

    @Test
    void sendingEarlyDataResultsInZeroRttPacket() throws IOException {
        // When
        stream.writeEarlyData(new byte[10], false);

        // Then
        verify(connection).sendZeroRtt(any(StreamFrame.class), any(Consumer.class));
    }

    @Test
    void sendingFinalEarlyDataResultsInClosingStream() throws IOException {
        // When
        stream.writeEarlyData(new byte[10], true);

        // Then
        ArgumentCaptor<QuicFrame> argumentCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(connection, atLeast(2)).sendZeroRtt(argumentCaptor.capture(), any(Consumer.class));
        assertThat(argumentCaptor.getAllValues()).hasSize(2);
        assertThat(((StreamFrame) argumentCaptor.getAllValues().get(0)).isFinal()).isFalse();
        assertThat(((StreamFrame) argumentCaptor.getAllValues().get(1)).isFinal()).isTrue();
    }

    @Test
    void sendingLargeEarlyDataResultsInMultiplePackets() throws IOException {
        // When
        stream.writeEarlyData(new byte[1500], false);

        // Then
        ArgumentCaptor<QuicFrame> argumentCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(connection, atLeast(2)).sendZeroRtt(argumentCaptor.capture(), any(Consumer.class));
        assertThat(argumentCaptor.getAllValues()).hasSize(2);
        assertThat(((StreamFrame) argumentCaptor.getAllValues().get(0)).getStreamData().length).isGreaterThan(1000);
        assertThat(((StreamFrame) argumentCaptor.getAllValues().get(1)).getStreamData().length).isGreaterThan(200);
        assertThat(argumentCaptor.getAllValues().stream().mapToInt(f -> ((StreamFrame) f).getStreamData().length).sum()).isEqualTo(1500);
    }

    @Test
    void earlyDataShouldBeLimitedToFlowControlLimit() throws Exception {
        // Given
        int maxData = 1000;
        FlowControl flowController = new FlowControl(maxData, maxData, maxData, maxData);
        FieldSetter.setField(connection, QuicConnectionImpl.class.getDeclaredField("flowController"), flowController);
        stream = new EarlyDataStream(Version.getDefault(), 0, connection, flowController, logger);

        // When
        stream.writeEarlyData(new byte[1500], false);

        // Then
        verify(connection, times(1)).sendZeroRtt(argThat(f -> ((StreamFrame) f).getStreamData().length <= 1000), any(Consumer.class));
    }

}