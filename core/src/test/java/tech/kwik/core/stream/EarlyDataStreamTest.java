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
package tech.kwik.core.stream;

import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.impl.QuicClientConnectionImpl;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.NullLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class EarlyDataStreamTest {

    private EarlyDataStream stream;
    private QuicClientConnectionImpl connection;
    private Logger logger;
    private StreamManager streamManager;

    @BeforeEach
    void initObjectUnderTest() {
        streamManager = mock(StreamManager.class);

        connection = mock(QuicClientConnectionImpl.class);
        int maxData = 5000;
        FlowControl flowController = new FlowControl(Role.Client, maxData, maxData, maxData, maxData);
        logger = new NullLogger();
        stream = new EarlyDataStream(Version.getDefault(), 0, connection, streamManager, flowController, logger);
    }

    @Test
    void sendingEarlyDataResultsInZeroRttPacket() throws IOException {
        // When
        stream.writeEarlyData(new byte[10], false, 10_000);

        // Then
        StreamFrame frame = captureFrameSentAndVerifyEncryptionLevel(connection, 1500, EncryptionLevel.ZeroRTT);
        assertThat(frame.getStreamData().length).isEqualTo(10);
    }

    @Test
    void sendingFinalEarlyDataResultsInClosingStream() throws IOException {
        // When
        stream.writeEarlyData(new byte[10], true, 10_000);

        // Then
        StreamFrame frame = captureFrameSentAndVerifyEncryptionLevel(connection, 1500, EncryptionLevel.ZeroRTT);
        assertThat(frame.isFinal()).isTrue();
        assertThat(frame.getStreamData().length).isEqualTo(10);
    }

    @Test
    void sendingLargeEarlyDataResultsInMultiplePackets() throws IOException {
        // When
        stream.writeEarlyData(new byte[1500], false, 10_000);

        // Then
        // Simulate first packet is sent (which will cause second send request to be queued)
        QuicFrame firstFrame = captureFrameSentAndVerifyEncryptionLevel(connection, 1300, EncryptionLevel.ZeroRTT);

        QuicFrame secondFrame = captureFrameSentAndVerifyEncryptionLevel(connection, 1300, EncryptionLevel.ZeroRTT);

        assertThat(((StreamFrame) firstFrame).getStreamData().length).isGreaterThan(1000);
        assertThat(((StreamFrame) secondFrame).getStreamData().length).isGreaterThan(200);
        assertThat(((StreamFrame) firstFrame).getStreamData().length + ((StreamFrame) secondFrame).getStreamData().length).isEqualTo(1500);
    }

    @Test
    void earlyDataShouldBeLimitedToFlowControlLimit() throws Exception {
        // Given
        int maxData = 1000;
        FlowControl flowController = new FlowControl(Role.Client, maxData, maxData, maxData, maxData);
        stream = new EarlyDataStream(Version.getDefault(), 0, connection, streamManager, flowController, logger);

        // When
        stream.writeEarlyData(new byte[1500], false, 10_000);

        // Then
        StreamFrame frame1 = captureFrameSentAndVerifyEncryptionLevel(connection, 1500, EncryptionLevel.ZeroRTT);
        assertThat(frame1.getLength()).isEqualTo(1000);
    }

    @Test
    void earlyDataShouldBeLimitedToInitalMaxData() throws Exception {
        // When
        stream.writeEarlyData(new byte[1500], true, 500);  // earlyDataSizeLeft should be set to initial max data from session ticket

        // Then
        StreamFrame frame1 = captureFrameSentAndVerifyEncryptionLevel(connection, 1500, EncryptionLevel.ZeroRTT);
        assertThat(frame1.getLength()).isEqualTo(500);
    }

    @Test
    void whenEarlyDataIsLimitedStreamIsNotClosed() throws Exception {
        // When
        stream.writeEarlyData(new byte[1500], true, 500);

        StreamFrame streamFrame = captureFrameSentAndVerifyEncryptionLevel(connection, 1300, EncryptionLevel.ZeroRTT);

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
        StreamFrame zeroRttData = captureFrameSentAndVerifyEncryptionLevel(connection, 1500, EncryptionLevel.ZeroRTT);

        StreamFrame oneRttData = captureFrameSentAndVerifyEncryptionLevel(connection, 1500, EncryptionLevel.App);

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
        StreamFrame zeroRttData = captureFrameSentAndVerifyEncryptionLevel(connection, 1200, EncryptionLevel.ZeroRTT);

        stream.writeRemaining(false);

        StreamFrame oneRttData = captureFrameSentAndVerifyEncryptionLevel(connection, 1200, EncryptionLevel.App);

        StreamFrame oneRttData2 = captureFrameSentAndVerifyEncryptionLevel(connection, 1200, EncryptionLevel.App);

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

    StreamFrame captureFrameSentAndVerifyEncryptionLevel(QuicClientConnectionImpl connection, int maxFrameSize, EncryptionLevel expectedLevel) {
        ArgumentCaptor<Function<Integer, QuicFrame>> frameSupplierCaptor = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(frameSupplierCaptor.capture(), anyInt(), argThat(l -> l == expectedLevel), any(Consumer.class), anyBoolean());
        clearInvocations(connection);
        return (StreamFrame) frameSupplierCaptor.getValue().apply(maxFrameSize);
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