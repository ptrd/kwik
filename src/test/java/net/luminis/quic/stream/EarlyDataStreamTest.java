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

import net.luminis.quic.EncryptionLevel;
import net.luminis.quic.QuicClientConnectionImpl;
import net.luminis.quic.Role;
import net.luminis.quic.Version;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.NullLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

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
        FlowControl flowController = new FlowControl(Role.Client, maxData, maxData, maxData, maxData);
        logger = new NullLogger();
        stream = new EarlyDataStream(Version.getDefault(), 0, connection, flowController, logger);
    }

    @Test
    void sendingEarlyDataResultsInZeroRttPacket() throws IOException {
        // When
        stream.writeEarlyData(new byte[10], false, 10_000);

        // Then
        ArgumentCaptor<Function<Integer, QuicFrame>> captor = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(captor.capture(), anyInt(), argThat(l -> l == EncryptionLevel.ZeroRTT), any(Consumer.class));
        QuicFrame frame = captor.getValue().apply(1500);
        assertThat(((StreamFrame) frame).getStreamData().length).isEqualTo(10);
    }

    @Test
    void sendingFinalEarlyDataResultsInClosingStream() throws IOException {
        // When
        stream.writeEarlyData(new byte[10], true, 10_000);

        // Then
        ArgumentCaptor<Function<Integer, QuicFrame>> captor = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(captor.capture(), anyInt(), argThat(l -> l == EncryptionLevel.ZeroRTT), any(Consumer.class));
        QuicFrame frame = captor.getValue().apply(1500);
        assertThat(((StreamFrame) frame).isFinal()).isTrue();
        assertThat(((StreamFrame) frame).getStreamData().length).isEqualTo(10);
    }

    @Test
    void sendingLargeEarlyDataResultsInMultiplePackets() throws IOException {
        // When
        stream.writeEarlyData(new byte[1500], false, 10_000);

        // Then
        ArgumentCaptor<Function<Integer, QuicFrame>> frameSupplierCaptor = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(frameSupplierCaptor.capture(), anyInt(), argThat(l -> l == EncryptionLevel.ZeroRTT), any(Consumer.class));
        clearInvocations(connection);
        // Simulate first packet is sent (which will cause second send request to be queued)
        QuicFrame firstFrame = frameSupplierCaptor.getValue().apply(1300);

        ArgumentCaptor<Function<Integer, QuicFrame>> frameSupplierCaptor2 = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(frameSupplierCaptor2.capture(), anyInt(), argThat(l -> l == EncryptionLevel.ZeroRTT), any(Consumer.class));
        QuicFrame secondFrame = frameSupplierCaptor.getValue().apply(1300);

        assertThat(((StreamFrame) firstFrame).getStreamData().length).isGreaterThan(1000);
        assertThat(((StreamFrame) secondFrame).getStreamData().length).isGreaterThan(200);
        assertThat(((StreamFrame) firstFrame).getStreamData().length + ((StreamFrame) secondFrame).getStreamData().length).isEqualTo(1500);
    }

    @Test
    void earlyDataShouldBeLimitedToFlowControlLimit() throws Exception {
        // Given
        int maxData = 1000;
        FlowControl flowController = new FlowControl(Role.Client, maxData, maxData, maxData, maxData);
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

        ArgumentCaptor<Function<Integer, QuicFrame>> frameSupplierCaptor = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(frameSupplierCaptor.capture(), anyInt(), argThat(l -> l == EncryptionLevel.ZeroRTT), any(Consumer.class));
        StreamFrame streamFrame = (StreamFrame) frameSupplierCaptor.getValue().apply(1300);

        // Then
        assertThat(streamFrame.isFinal()).isFalse();
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
        ArgumentCaptor<Function<Integer, QuicFrame>> frameSupplierCaptor = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(frameSupplierCaptor.capture(), anyInt(), argThat(l -> l == EncryptionLevel.ZeroRTT), any(Consumer.class));
        clearInvocations(connection);
        StreamFrame zeroRttData = (StreamFrame) frameSupplierCaptor.getValue().apply(1500);

        ArgumentCaptor<Function<Integer, QuicFrame>> frameSupplierCaptor2 = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(frameSupplierCaptor2.capture(), anyInt(), argThat(l -> l == EncryptionLevel.App), any(Consumer.class));
        StreamFrame oneRttData = (StreamFrame) frameSupplierCaptor2.getValue().apply(1500);

        byte[] transmittedData = transmittedByteStream(List.of(zeroRttData, oneRttData));
        assertThat(transmittedData).isEqualTo(data);
        assertThat(zeroRttData.isFinal()).isFalse();
        assertThat(oneRttData.isFinal()).isTrue();
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

        // Then
        ArgumentCaptor<Function<Integer, QuicFrame>> frameSupplierCaptor = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(frameSupplierCaptor.capture(), anyInt(), argThat(l -> l == EncryptionLevel.ZeroRTT), any(Consumer.class));
        clearInvocations(connection);
        StreamFrame zeroRttData = (StreamFrame) frameSupplierCaptor.getValue().apply(1200);

        stream.writeRemaining(false);

        ArgumentCaptor<Function<Integer, QuicFrame>> frameSupplierCaptor2 = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(frameSupplierCaptor2.capture(), anyInt(), argThat(l -> l == EncryptionLevel.App), any(Consumer.class));
        clearInvocations(connection);
        StreamFrame oneRttData = (StreamFrame) frameSupplierCaptor2.getValue().apply(1200);

        ArgumentCaptor<Function<Integer, QuicFrame>> frameSupplierCaptor3 = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(frameSupplierCaptor3.capture(), anyInt(), argThat(l -> l == EncryptionLevel.App), any(Consumer.class));
        StreamFrame oneRttData2 = (StreamFrame) frameSupplierCaptor3.getValue().apply(1200);

        byte[] transmittedData = transmittedByteStream(List.of(oneRttData, oneRttData2));
        assertThat(transmittedData).isEqualTo(data);
        assertThat(oneRttData.getOffset()).isEqualTo(0);
        assertThat(oneRttData2.isFinal()).isTrue();
    }

    @Test
    void whenAllEarlyDataWasSentNoRemainingShouldBeSend() throws Exception {
        // Given
        stream.writeEarlyData(new byte[100], true, 10_000);

        // When
        clearInvocations(connection);
        stream.writeRemaining(true);

        // Then
        verify(connection, never()).send(any(Function.class), anyInt(), any(EncryptionLevel.class), any(Consumer.class));
    }

    byte[] transmittedByteStream(ArgumentCaptor<QuicFrame> argumentCaptor) {
        int totalSize = argumentCaptor.getAllValues().stream().mapToInt(f -> ((StreamFrame) f).getStreamData().length).sum();
        ByteBuffer buffer = ByteBuffer.allocate(totalSize);
        argumentCaptor.getAllValues().stream()
                .map(frame -> ((StreamFrame) frame).getStreamData())
                .forEach(byteArray -> buffer.put(byteArray));
        return buffer.array();
    }

    byte[] transmittedByteStream(List<StreamFrame> streamFrames) {
        int totalSize = streamFrames.stream().mapToInt(f -> f.getLength()).sum();
        ByteBuffer buffer = ByteBuffer.allocate(totalSize);
        streamFrames.stream()
                .map(frame -> frame.getStreamData())
                .forEach(byteArray -> buffer.put(byteArray));
        return buffer.array();
    }
}