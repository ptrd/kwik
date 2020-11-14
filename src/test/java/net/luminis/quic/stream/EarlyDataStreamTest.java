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

import net.luminis.quic.QuicClientConnectionImpl;
import net.luminis.quic.Version;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.NullLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class EarlyDataStreamTest {

    private EarlyDataStream stream;
    private QuicClientConnectionImpl connection;
    private Logger logger;

    @BeforeEach
    void initObjectUnderTest() {
        connection = mock(QuicClientConnectionImpl.class);
        when(connection.getMaxShortHeaderPacketOverhead()).thenReturn(29);
        int maxData = 5000;
        FlowControl flowController = new FlowControl(maxData, maxData, maxData, maxData);
        logger = new NullLogger();
        stream = new EarlyDataStream(Version.getDefault(), 0, connection, flowController, logger);
    }

    @Test
    void sendingEarlyDataResultsInZeroRttPacket() throws IOException {
        // When
        stream.writeEarlyData(new byte[10], false, 10_000);

        // Then
        verify(connection).sendZeroRtt(any(StreamFrame.class), any(Consumer.class));
    }

    @Test
    void sendingFinalEarlyDataResultsInClosingStream() throws IOException {
        // When
        stream.writeEarlyData(new byte[10], true, 10_000);

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
        stream.writeEarlyData(new byte[1500], false, 10_000);

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
        stream = new EarlyDataStream(Version.getDefault(), 0, connection, flowController, logger);

        // When
        stream.writeEarlyData(new byte[1500], false, 10_000);

        // Then
        verify(connection, times(1)).sendZeroRtt(any(QuicFrame.class), any(Consumer.class));
        verify(connection, times(1)).sendZeroRtt(argThat(f -> ((StreamFrame) f).getStreamData().length == 1000), any(Consumer.class));
    }

    @Test
    void earlyDataShouldBeLimitedToInitalMaxData() throws Exception {
        // When
        stream.writeEarlyData(new byte[1500], true, 500);

        // Then
        verify(connection, times(1)).sendZeroRtt(any(QuicFrame.class), any(Consumer.class));
        verify(connection, times(1)).sendZeroRtt(argThat(f -> ((StreamFrame) f).getStreamData().length <= 500), any(Consumer.class));
    }

    @Test
    void whenEarlyDataIsLimitedStreamIsNotClosed() throws Exception {
        // When
        stream.writeEarlyData(new byte[1500], true, 500);

        // Then
        verify(connection, times(1)).sendZeroRtt(argThat(f -> ((StreamFrame) f).isFinal() == false), any(Consumer.class));
    }

    @Test
    void whenWritingRemainingAllDataShouldHaveBeenSent() throws Exception {
        // Given
        byte[] data = new byte[1500];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }

        // When
        stream.writeEarlyData(data, true, 500);
        stream.writeRemaining(true);

        // Then
        ArgumentCaptor<QuicFrame> argumentCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(connection, atLeast(1)).sendZeroRtt(argumentCaptor.capture(), any(Consumer.class));
        verify(connection, atLeast(1)).send(argumentCaptor.capture(), any(Consumer.class), anyBoolean());
        byte[] transmittedData = transmittedByteStream(argumentCaptor);
        assertThat(transmittedData).isEqualTo(data);
        StreamFrame lastFrame = ((StreamFrame) argumentCaptor.getAllValues().get(argumentCaptor.getAllValues().size() - 1));
        assertThat(lastFrame.isFinal()).isTrue();
    }

    @Test
    void whenEarlyDataWasNotAcceptedWritingRemainingShouldSendAll() throws Exception {
        // Given
        byte[] data = new byte[1500];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }

        // When
        stream.writeEarlyData(data, true, 500);
        stream.writeRemaining(false);

        // Then
        ArgumentCaptor<QuicFrame> argumentCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(connection, atLeast(1)).send(argumentCaptor.capture(), any(Consumer.class), anyBoolean());
        byte[] transmittedData = transmittedByteStream(argumentCaptor);
        assertThat(transmittedData).isEqualTo(data);
        StreamFrame firstFrame = (StreamFrame) argumentCaptor.getAllValues().get(0);
        assertThat(firstFrame.getOffset()).isEqualTo(0);
        StreamFrame lastFrame = (StreamFrame) argumentCaptor.getAllValues().get(argumentCaptor.getAllValues().size() - 1);
        assertThat(lastFrame.isFinal()).isTrue();
    }

    @Test
    void whenAllEarlyDataWasSentNoRemainingShouldBeSend() throws Exception {
        // Given
        stream.writeEarlyData(new byte[100], true, 10_000);

        // When
        clearInvocations(connection);
        stream.writeRemaining(true);

        // Then
        verify(connection, never()).send(any(QuicFrame.class), any(Consumer.class));
    }

    byte[] transmittedByteStream(ArgumentCaptor<QuicFrame> argumentCaptor) {
        int totalSize = argumentCaptor.getAllValues().stream().mapToInt(f -> ((StreamFrame) f).getStreamData().length).sum();
        ByteBuffer buffer = ByteBuffer.allocate(totalSize);
        argumentCaptor.getAllValues().stream()
                .map(frame -> ((StreamFrame) frame).getStreamData())
                .forEach(byteArray -> buffer.put(byteArray));
        return buffer.array();
    }

}