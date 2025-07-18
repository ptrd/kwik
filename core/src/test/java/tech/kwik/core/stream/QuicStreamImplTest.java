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
package tech.kwik.core.stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatcher;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.frame.MaxStreamDataFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.frame.ResetStreamFrame;
import tech.kwik.core.frame.StopSendingFrame;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.generic.IntegerTooLargeException;
import tech.kwik.core.generic.InvalidIntegerEncodingException;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.test.FieldReader;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;


class QuicStreamImplTest {

    private static long originalWaitForNextFrameTimeoutValue;
    private QuicConnectionImpl connection;
    private QuicStreamImpl quicStream;
    private StreamManager streamManager;
    private Logger logger;
    private Random randomGenerator = new Random();
    private Role role;

    //region setup
    @BeforeEach
    void setFiniteWaitForNextFrameTimeout() {
        originalWaitForNextFrameTimeoutValue = StreamInputStreamImpl.waitForNextFrameTimeout;
        StreamInputStreamImpl.waitForNextFrameTimeout = 5;
    }

    @AfterEach
    void resetWaitForNextFrameTimeout() {
        StreamInputStreamImpl.waitForNextFrameTimeout = originalWaitForNextFrameTimeoutValue;
    }

    @BeforeEach
    void createDefaultMocksAndObjectUnderTest() {
        long initialMaxStreamData = 9999;
        connection = mock(QuicConnectionImpl.class);
        streamManager = mock(StreamManager.class);
        when(streamManager.getMaxBidirectionalStreamBufferSize()).thenReturn(initialMaxStreamData);
        when(streamManager.getMaxUnidirectionalStreamBufferSize()).thenReturn(initialMaxStreamData);
        logger = mock(Logger.class);
        role = Role.Client;

        quicStream = new QuicStreamImpl(0, role, connection, streamManager, new FlowControl(Role.Client, 9999, 9999, 9999, 9999), logger);
    }
    //endregion

    //region stream properties (no read or write)
    @Test
    void whenRoleIsClientThenClientInitiatedStreamShouldBeSelfInitiated() {
        // Given
        role = Role.Client;
        int streamId = 0;  // bidirectional client initiated

        // When
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));

        assertThat(quicStream.isSelfInitiated()).isTrue();
        assertThat(quicStream.isPeerInitiated()).isFalse();
    }

    @Test
    void whenRoleIsClientThenServerInitiatedStreamShouldBePeerInitiated() {
        // Given
        role = Role.Client;
        int streamId = 1;  // bidirectional server initiated

        // When
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));

        assertThat(quicStream.isPeerInitiated()).isTrue();
        assertThat(quicStream.isSelfInitiated()).isFalse();
    }

    @Test
    void whenRoleIsServerThenClientInitiatedStreamShouldBePeerInitiated() {
        // Given
        role = Role.Server;
        int streamId = 0;  // bidirectional client initiated

        // When
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));

        assertThat(quicStream.isPeerInitiated()).isTrue();
        assertThat(quicStream.isSelfInitiated()).isFalse();
    }

    @Test
    void whenRoleIsServerThenServerInitiatedStreamShouldBeSelfInitiated() {
        // Given
        role = Role.Server;
        int streamId = 1;  // bidirectional server initiated

        // When
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));

        assertThat(quicStream.isSelfInitiated()).isTrue();
        assertThat(quicStream.isPeerInitiated()).isFalse();
    }

    @Test
    void isUnidirectional() {
        QuicStreamImpl clientInitiatedStream = new QuicStreamImpl(2, role, mock(QuicConnectionImpl.class), streamManager, mock(FlowControl.class));
        assertThat(clientInitiatedStream.isUnidirectional()).isTrue();

        QuicStreamImpl serverInitiatedStream = new QuicStreamImpl(3, role, mock(QuicConnectionImpl.class), streamManager, mock(FlowControl.class));
        assertThat(serverInitiatedStream.isUnidirectional()).isTrue();
    }

    @Test
    void isClientInitiatedBidirectional() {
        QuicStreamImpl stream = new QuicStreamImpl(0, role, mock(QuicConnectionImpl.class), streamManager, mock(FlowControl.class));
        assertThat(stream.isClientInitiatedBidirectional()).isTrue();
    }

    @Test
    void isServerInitiatedBidirectional() {
        QuicStreamImpl stream = new QuicStreamImpl(1, role, mock(QuicConnectionImpl.class), streamManager, mock(FlowControl.class));
        assertThat(stream.isServerInitiatedBidirectional()).isTrue();
    }
    //endregion

    //region inputstream read / available
    @Test
    void testReadSingleFinalStreamFrame() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "data".getBytes(), true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("data".getBytes());
    }

    @Test
    void testReadStreamWithNonAsciiBytes() throws Exception {
        byte[] data = {
                0x00, 0x01, 0x02, (byte) 0xff, (byte) 0xfe, (byte) 0xfd
        };
        quicStream.addStreamData(resurrect(new StreamFrame(0, data, true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo(data);
    }

    @Test
    void testReadStreamWithFFByte() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, new byte[] { (byte) 0xff }, true)));

        assertThat(quicStream.getInputStream().read()).isEqualTo(0xff);
    }

    @Test
    void testAvailableBytesForSingleFrame() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "data".getBytes(), true)));

        assertThat(quicStream.getInputStream().available()).isEqualTo(4);
    }

    @Test
    void testAvailableBytesForSingleFrameAfterRead() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "data".getBytes(), true)));
        InputStream inputStream = quicStream.getInputStream();
        inputStream.read();

        assertThat(inputStream.available()).isEqualTo(3);
    }

    @Test
    void testAvailableAfterReadingAllAvailable() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "data".getBytes(), false)));
        InputStream inputStream = quicStream.getInputStream();
        inputStream.read(new byte[4]);

        assertThat(inputStream.available()).isEqualTo(0);
    }

    @Test
    public void testReadMultipleStreamFrames() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 6, "second-final".getBytes(), true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-final".getBytes());
    }

    @Test
    public void testAvailableWithMultipleStreamFrames() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 6, "second-final".getBytes(), true)));

        assertThat(quicStream.getInputStream().available()).isGreaterThan("first-".getBytes().length - 1);
    }

    @Test
    public void testAvailableAfterReadingFirstFrame() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 6, "second-final".getBytes(), true)));

        InputStream inputStream = quicStream.getInputStream();
        assertThat(inputStream.available()).isGreaterThan("first-".getBytes().length - 1);

        inputStream.read(new byte["first-".getBytes().length]);
        assertThat(inputStream.available()).isEqualTo("second-final".getBytes().length);
    }

    @Test
    void testAddDuplicateStreamFrames() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 6, "second-final".getBytes(), true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-final".getBytes());
    }

    @Test
    void testAddNonContiguousStreamFrames() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 13, "third-final".getBytes(), true)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 6, "second-".getBytes(), false)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-third-final".getBytes());
    }

    @Test
    void testAddMultipleOutOfOrderFrames() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 13, "third-".getBytes(), false)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 19, "forth-final".getBytes(), true)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 6, "second-".getBytes(), false)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-third-forth-final".getBytes());
    }

    @Test
    void testAddInterleavedOutOfOrderFrames() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 13, "third-".getBytes(), false)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 6, "second-".getBytes(), false)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 19, "forth-final".getBytes(), true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-third-forth-final".getBytes());
    }

    @Test
    void testReadBlocksTillContiguousFrameIsAvailalble() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.addStreamData(resurrect(new StreamFrame(0, 13, "third-final".getBytes(), true)));

        byte[] buffer = new byte[100];
        int initialReadCount = quicStream.getInputStream().read(buffer);

        try {
            quicStream.getInputStream().read(buffer, initialReadCount, buffer.length - initialReadCount);

            // It should not get here
            fail("read method should not successfully return");
        }
        catch (SocketTimeoutException e) {
            // This is expected, as the read method should have blocked for QuicStream.waitForNextFrameTimeout seconds.

            // Now continue the test by offering the next frame
            quicStream.addStreamData(resurrect(new StreamFrame(0, 6, "second-".getBytes(), false)));

            // Read more
            int lastRead = quicStream.getInputStream().read(buffer, initialReadCount, buffer.length - initialReadCount);
            assertThat(buffer).startsWith("first-second-third-final".getBytes());
            assertThat(initialReadCount + lastRead).isEqualTo("first-second-third-final".getBytes().length);
        }
    }

    @Test
    void testReadAtEndOfStreamReturns() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "1".getBytes(), true)));
        InputStream inputStream = quicStream.getInputStream();

        assertThat(inputStream.read()).isEqualTo(49);
        assertThat(inputStream.read()).isEqualTo(-1);
        assertThat(inputStream.read()).isEqualTo(-1);
    }

    @Test
    void testAvailableAtEndOfStreamReturnsZero() throws Exception {
        quicStream.addStreamData(resurrect(new StreamFrame(0, "1".getBytes(), true)));
        InputStream inputStream = quicStream.getInputStream();

        assertThat(inputStream.read()).isEqualTo(49);
        assertThat(inputStream.read()).isEqualTo(-1);
        assertThat(inputStream.available()).isEqualTo(0);
        assertThat(inputStream.read()).isEqualTo(-1);  // Important: read() must keep on returning -1!
    }

    @Test
    void closingInputStreamShouldUnblockWatingReader() throws Exception {
        StreamInputStreamImpl.waitForNextFrameTimeout = Integer.MAX_VALUE;  // No finite wait for this test!
        quicStream = new QuicStreamImpl(0, role, connection, streamManager, new FlowControl(Role.Client, 9999, 9999, 9999, 9999), logger);
        InputStream inputStream = quicStream.getInputStream();

        Thread blockingReader = new Thread(() -> {
            try {
                inputStream.read(new byte[1024]);
            } catch (IOException e) {}
        });
        blockingReader.start();

        Thread.sleep(3);
        assertThat(blockingReader.getState()).isEqualTo(Thread.State.TIMED_WAITING);

        inputStream.close();
        Thread.sleep(3);
        assertThat(blockingReader.getState()).isIn(Thread.State.TERMINATED, Thread.State.RUNNABLE);
    }
    //endregion

    //region inputstream read
    @Test
    void readReturnsMinusOneWhenEndOfStreamIsReached() throws Exception {
        // Given
        quicStream.addStreamData(new StreamFrame(0, new byte[10], true));
        InputStream inputStream = quicStream.getInputStream();

        // When
        int read = inputStream.read(new byte[50]);
        assertThat(read).isEqualTo(10);

        // Then
        read = inputStream.read(new byte[50]);
        assertThat(read).isEqualTo(-1);
    }

    @Test
    void readReturnsZeroWhenRequestedReadLengthIsZero() throws Exception {
        // Given
        quicStream.addStreamData(new StreamFrame(0, new byte[10], true));

        // When
        int read = quicStream.getInputStream().read(new byte[100], 0, 0);

        // Then
        assertThat(read).isEqualTo(0);
    }

    @Test
    void availableReturnsZeroWhenEndOfStreamIsReached() throws Exception {
        // Given
        quicStream.addStreamData(new StreamFrame(0, new byte[10], true));
        InputStream inputStream = quicStream.getInputStream();

        // When
        int read = inputStream.read(new byte[50]);
        assertThat(read).isEqualTo(10);

        // Then
        int available = inputStream.available();
        assertThat(available).isEqualTo(0);
    }

    @Test
    void receivingEmptyLastFrameTerminatesBlockingRead() throws Exception {
        StreamInputStreamImpl.waitForNextFrameTimeout = 10_000;  // Just a large value, but not infinite to avoid a failing test to block forever.
        // Given
        InputStream inputStream = quicStream.getInputStream();
        quicStream.addStreamData(resurrect(new StreamFrame(0, "data".getBytes(), false)));
        int firstRead = inputStream.read(new byte[100]);

        // When
        // Async add of stream frame while read is already blocking
        new Thread(() -> {
            try {
                Thread.sleep(100);   // Wait long enough to have reader thread (the main thread) block _before_ the frame is added.
            } catch (InterruptedException e) {}
            try {
                quicStream.addStreamData(resurrect(new StreamFrame(0, 4, new byte[0], true)));
            }
            catch (TransportError e) {
                throw new RuntimeException(e);
            }
        }).start();

        Instant startRead = Instant.now();
        int secondRead = inputStream.read(new byte[100]);
        Duration readDuration = Duration.between(startRead, Instant.now());

        // Then
        assertThat(firstRead).isEqualTo(4);
        assertThat(secondRead).isEqualTo(-1);
        // If read was very fast, it is unlikely the read was first in blocking state, in which case this test does not test what it ought to be.
        // Of course, speed of execution depends on hardware and may vary, but it seems reasonable to assume that:
        // - starting a thread takes less than 50 ms
        // - a non-blocking read takes (far) less than 50 ms
        assertThat(readDuration).isGreaterThan(Duration.of(50, ChronoUnit.MILLIS));
    }

    @Test
    void cantReadFromSelfInitiatedUnidirectionalStream() throws Exception {
        // Given
        int streamId = 0x02;  // client initiated unidirectional
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));

        // When
        int read = quicStream.getInputStream().read(new byte[1]);

        assertThat(read).isEqualTo(-1);
    }
    //endregion

    //region inputstream flow control updates
    @Test
    void testStreamFlowControlUpdates() throws Exception {
        float factor = StreamInputStreamImpl.receiverMaxDataIncrementFactor;
        int initialWindow = 1000;
        when(streamManager.getMaxBidirectionalStreamBufferSize()).thenReturn((long) initialWindow);
        when(streamManager.getMaxUnidirectionalStreamBufferSize()).thenReturn((long) initialWindow);

        quicStream = new QuicStreamImpl(0, role, connection, streamManager, mock(FlowControl.class), logger);  // Re-instantiate because constructor reads initial max stream data from connection

        quicStream.addStreamData(resurrect(new StreamFrame(0, new byte[1000], true)));
        InputStream inputStream = quicStream.getInputStream();

        inputStream.read(new byte[(int) (initialWindow * factor * 0.8)]);
        verify(connection, never()).send(any(QuicFrame.class), any(Consumer.class));

        inputStream.read(new byte[(int) (initialWindow * factor * 0.2 - 1)]);
        verify(connection, never()).send(any(QuicFrame.class), any(Consumer.class));

        inputStream.read(new byte[2]);
        verify(connection, times(1)).send(any(MaxStreamDataFrame.class), any(Consumer.class), anyBoolean());

        inputStream.read(new byte[(int) (initialWindow * factor)]);
        verify(connection, times(1)).send(any(MaxStreamDataFrame.class), any(Consumer.class), anyBoolean());

        inputStream.read(new byte[2]);
        verify(connection, times(2)).send(any(MaxStreamDataFrame.class), any(Consumer.class), anyBoolean());

        clearInvocations();
        inputStream.read(new byte[(int) (initialWindow * factor * 3.1)]);
        verify(connection, times(3)).send(any(MaxStreamDataFrame.class), any(Consumer.class), anyBoolean());
    }

    @Test
    void receivingStreamFrameWithOffsetBeyondFlowControLimitShouldThrow() throws Exception {
        // Given

        // When
        assertThatThrownBy(() ->
                // When
                quicStream.addStreamData(resurrect(new StreamFrame(0, 9999, new byte[1], false))))
                // Then
                .isInstanceOf(TransportError.class);
    }

    @Test
    void testReceivingStreamFrameWithOffsetBelowFlowControLimit() throws Exception {
        // Given

        // When
        assertThatCode(() ->
                // When
                quicStream.addStreamData(resurrect(new StreamFrame(0, 9998, new byte[1], false))))
                // Then
                .doesNotThrowAnyException();
    }
    //endregion

    //region inputstream abort reading
    @Test
    void afterAbortReadingNextReadShouldThrow() throws Exception {
        // When
        quicStream.abortReading(9);

        // Then
        assertThatThrownBy(() ->
                quicStream.getInputStream().read(new byte[10])
        ).isInstanceOf(IOException.class)
                .hasMessageContaining("closed");
    }

    @Test
    void whenAbortReadingBlockingReadShouldBeInterupted() throws Exception {
        // Given
        StreamInputStreamImpl.waitForNextFrameTimeout = Integer.MAX_VALUE;

        AtomicReference<Exception> thrownException = new AtomicReference<>();
        new Thread(() -> {
            try {
                quicStream.getInputStream().read(new byte[10]);
            }
            catch (IOException e) {
                thrownException.set(e);
            }
        }).start();

        // Then
        quicStream.abortReading(9);
        Thread.sleep(10);
        assertThat(thrownException.get())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("closed");
    }

    @Test
    void whenAbortReadingStopSendingShouldBeSent() throws Exception {
        // When
        quicStream.abortReading(9);

        // Then
        verify(connection).send(argThat(f -> f instanceof StopSendingFrame), any(Consumer.class), anyBoolean());
    }

    @Test
    void whenAllDataIsReceivedAbortReadingShouldNotTriggerStopSending() throws Exception {
        // Given
        quicStream.addStreamData(resurrect(new StreamFrame(0, "data".getBytes(), true)));

        // When
        quicStream.abortReading(9);

        // Then
        verify(connection, never()).send(argThat(f -> f instanceof StopSendingFrame), any(Consumer.class), anyBoolean());
    }

    @Test
    void afterAbortReadingInputForUnidirectionStreamStreamShouldBeClosed() throws Exception {
        // Given
        int streamId = 0x03;  // server initiated unidirectional
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));

        // When
        quicStream.abortReading(9);

        // Then
        verify(streamManager).streamClosed(eq(quicStream.streamId));
    }

    @Test
    void afterAbortReadingIncomingDataShouldBeDiscarded() throws Exception {
        // Given
        int streamId = 0x01;
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));
        quicStream.addStreamData(resurrect(new StreamFrame(streamId, 0, new byte[1000], false)));
        quicStream.abortReading(9);

        // When
        quicStream.addStreamData(new StreamFrame(streamId, 2000, new byte[1000], false));

        // Then
        StreamInputStream streamInputStream = (StreamInputStream) quicStream.getInputStream();
        ReceiveBufferImpl receiveBuffer = (ReceiveBufferImpl) new FieldReader(streamInputStream, "receiveBuffer").read();
        assertThat(receiveBuffer.bufferedOutOfOrderData()).isEqualTo(0);
    }
    //endregion

    //region reset affects read
    @Test
    void whenResetIsReceivedReadIsInterruptedWithException() throws Exception {
        // Given
        AtomicReference<Exception> thrownException = new AtomicReference<>();
        new Thread(() -> {
            try {
                quicStream.getInputStream().read(new byte[10]);
            }
            catch (IOException e) {
                thrownException.set(e);
            }
        }).start();

        // When
        quicStream.terminateStream(9, 49493);

        // Then
        Thread.sleep(5);
        assertThat(thrownException.get())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("reset by peer");
    }
    //endregion

    //region receive stream frame
    @Test
    void receivingStreamFrameForSelfInitiatedUnidirectionalShouldThrow() throws Exception {
        // Given
        role = Role.Client;
        int streamId = 0x02;  // client initiated unidirectional
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));

        // When
        assertThatThrownBy(() ->
                // When
                quicStream.addStreamData(resurrect(new StreamFrame(streamId, new byte[1], false))))
                // Then
                .isInstanceOf(TransportError.class);
    }

    @Test
    void receivingStreamFrameForPeerInitiatedUnidirectionalShouldBePossible() throws Exception {
        // Given
        role = Role.Client;
        int streamId = 0x03;  // server initiated unidirectional
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));

        // When
        assertThatCode(() ->
                // When
                quicStream.addStreamData(resurrect(new StreamFrame(streamId, new byte[1], false))))
                // Then
                .doesNotThrowAnyException();
    }
    //endregion

    //region outputstream write
    @Test
    void testStreamOutputWithByteArray() throws Exception {
        // Given
        quicStream.getOutputStream().write("hello world".getBytes());

        // When
        QuicFrame streamFrame = captureSendFunction(connection).apply(1500);

        // Then
        assertThat(((StreamFrame) streamFrame).getStreamData()).isEqualTo("hello world".getBytes());
    }

    @Test
    void testStreamOutputWithByteArrayFragment() throws Exception {
        // Given
        quicStream.getOutputStream().write(">> hello world <<".getBytes(), 3, 11);

        // When
        QuicFrame streamFrame = captureSendFunction(connection).apply(1500);

        // Then
        assertThat(((StreamFrame) streamFrame).getStreamData()).isEqualTo("hello world".getBytes());
    }

    @Test
    void testStreamOutputWithSingleByte() throws Exception {
        // Given
        quicStream.getOutputStream().write(0x23);  // ASCII 23 == '#'

        // When
        QuicFrame streamFrame = captureSendFunction(connection).apply(1500);

        // Then
        assertThat(((StreamFrame) streamFrame).getStreamData()).isEqualTo("#".getBytes());
    }

    @Test
    void testStreamOutputMultipleFrames() throws Exception {
        // Given
        quicStream.getOutputStream().write("hello ".getBytes());
        quicStream.getOutputStream().write("world".getBytes());

        // When
        QuicFrame streamFrame = captureSendFunction(connection).apply(1500);

        // Then
        assertThat(((StreamFrame) streamFrame).getStreamData()).isEqualTo("hello world".getBytes());
    }

    @Test
    void testCloseSendsFinalFrame() throws Exception {
        // Given
        quicStream.getOutputStream().write("hello world!".getBytes());
        quicStream.getOutputStream().close();

        // When
        QuicFrame streamFrame = captureSendFunction(connection).apply(1500);

        // Then
        assertThat(((StreamFrame) streamFrame).getStreamData()).isEqualTo("hello world!".getBytes());
        assertThat(((StreamFrame) streamFrame).isFinal()).isTrue();
    }

    @Test
    void testOutputWithByteArrayLargerThanMaxPacketSizeIsSplitOverMultiplePackets() throws Exception {
        byte[] data = generateByteArray(1700);
        quicStream.getOutputStream().write(data);

        ArgumentCaptor<Function<Integer, QuicFrame>> captor = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(captor.capture(), anyInt(), argThat(l -> l == EncryptionLevel.App), any(Consumer.class), anyBoolean());

        StreamFrame firstFrame = (StreamFrame) captor.getAllValues().get(0).apply(1200);
        verify(connection, times(2)).send(captor.capture(), anyInt(), argThat(l -> l == EncryptionLevel.App), any(Consumer.class), anyBoolean());
        StreamFrame secondFrame = (StreamFrame) captor.getAllValues().get(1).apply(1200);

        // This is what the test is about: the first frame should be less than max packet size.
        assertThat(firstFrame.getFrameLength()).isLessThanOrEqualTo(1200);
        // And of course, the remaining bytes should be in the second frame.
        int totalFrameLength = firstFrame.getLength() + secondFrame.getLength();
        assertThat(totalFrameLength).isEqualTo(data.length);

        // Also, the content should be copied correctly over the two frames:
        byte[] reconstructedContent = new byte[firstFrame.getStreamData().length + secondFrame.getStreamData().length];
        System.arraycopy(firstFrame.getStreamData(), 0, reconstructedContent, 0, firstFrame.getStreamData().length);
        System.arraycopy(secondFrame.getStreamData(), 0, reconstructedContent, firstFrame.getStreamData().length, secondFrame.getStreamData().length);
        assertThat(reconstructedContent).isEqualTo(data);
    }

    @Test
    void writingLessThanSendBufferSizeDoesNotBlock() throws Exception {
        // Given
        OutputStream outputStream = quicStream.getOutputStream();

        // When
        AtomicBoolean writeSucceeded = new AtomicBoolean(false);
        AtomicReference<Exception> exception = new AtomicReference<>();
        Thread asyncWriter = new Thread(() -> {
            try {
                outputStream.write(new byte[50 * 1024]);
                writeSucceeded.set(true);
            } catch (IOException e) {
                exception.set(e);
            }
        });
        asyncWriter.start();
        asyncWriter.join(500);
        asyncWriter.interrupt();

        assertThat(writeSucceeded.get()).isTrue();
    }

    @Test
    void writingMoreThanSendBufferSizeShouldBlock() throws Exception {
        // Given
        OutputStream outputStream = quicStream.getOutputStream();
        outputStream.write(new byte[50 * 1024]);

        // When
        AtomicBoolean writeSucceeded = new AtomicBoolean(false);
        AtomicReference<Exception> exception = new AtomicReference<>();
        Thread asyncWriter = new Thread(() -> {
            try {
                outputStream.write(new byte[10]);
                writeSucceeded.set(true);
            } catch (IOException e) {
                exception.set(e);
            }
        });
        asyncWriter.start();
        asyncWriter.join(500);  // Wait for thread to complete (which it won't ;-))
        asyncWriter.interrupt();      // Make sure thread ends
        asyncWriter.join(500);  // And wait for thread finish

        assertThat(writeSucceeded.get()).isFalse();
        assertThat(exception.get()).isInstanceOf(InterruptedIOException.class);
    }

    @Test
    void writingMoreThanSendBufferSizeAtOnceShouldBlock() throws Exception {
        // Given
        OutputStream outputStream = quicStream.getOutputStream();

        // When
        AtomicBoolean writeSucceeded = new AtomicBoolean(false);
        AtomicReference<Exception> exception = new AtomicReference<>();
        Thread asyncWriter = new Thread(() -> {
            try {
                outputStream.write(new byte[66 * 1024]);
                writeSucceeded.set(true);
            } catch (IOException e) {
                exception.set(e);
            }
        });
        asyncWriter.start();
        asyncWriter.join(500);  // Wait for thread to complete (which it won't ;-))
        asyncWriter.interrupt();      // Make sure thread ends
        asyncWriter.join(500);  // And wait for thread finish

        assertThat(writeSucceeded.get()).isFalse();
        assertThat(exception.get()).isInstanceOf(InterruptedIOException.class);
    }

    @Test
    void testWritingMoreThanSendBufferSize() throws Exception {
        // Given
        int sendBufferSize = 77;
        quicStream = new QuicStreamImpl(Version.getDefault(), 0, role, connection, streamManager,
                new FlowControl(Role.Client, 9999, 9999, 9999, 9999),
                logger, sendBufferSize);
        OutputStream outputStream = quicStream.getOutputStream();

        // When
        byte[] data = new byte[1000];
        randomGenerator.nextBytes(data);
        Thread asyncWriter = new Thread(() -> {
            try {
                outputStream.write(data);
                outputStream.close();
            } catch (IOException e) {
            }
        });
        asyncWriter.start();
        // Give writer/sender a change to start sending.
        Thread.sleep(10);

        ByteBuffer dataSent = ByteBuffer.allocate(1000);
        StreamFrame lastFrame = null;
        // Then: collect data that is sent (when frame supplier function is called); should result in same data that is sent.
        do {
            ArgumentCaptor<Function<Integer, QuicFrame>> sendFunctionCaptor = ArgumentCaptor.forClass(Function.class);
            verify(connection, atLeastOnce()).send(sendFunctionCaptor.capture(), anyInt(), any(EncryptionLevel.class), any(Consumer.class), anyBoolean());
            for (Function<Integer, QuicFrame> f: sendFunctionCaptor.getAllValues()) {
                QuicFrame frame = f.apply(1200);
                if (frame != null) {
                    lastFrame = (StreamFrame) frame;
                    dataSent.put(((StreamFrame) frame).getStreamData());
                }
            }
        }
        while (!lastFrame.isFinal());

        assertThat(dataSent.array()).isEqualTo(data);
    }

    @Test
    void cantWriteToPeerInitiatedUnidirectionalStream() throws Exception {
        // Given
        int streamId = 0x03;  // server initiated unidirectional
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));

        // When
        assertThatThrownBy(() ->
                // When
                quicStream.getOutputStream().write(new byte[1]))
                // Then
                .isInstanceOf(IOException.class)
                .hasMessageContaining("not writable");
    }
    //endregion

    //region outputstream flow control
    @Test
    void noMoreFlowControlCreditsShouldBeRequestedThanByteCountInBuffer() throws Exception {
        FlowControl flowController = mock(FlowControl.class);
        when(flowController.getFlowControlLimit(any(QuicStreamImpl.class))).thenReturn(1500L);
        quicStream = new QuicStreamImpl(0, role, connection, streamManager, flowController, logger);  // Re-instantiate to access to flow control object
        quicStream.getOutputStream().write(new byte[] { (byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe });

        // When
        QuicFrame streamFrame = captureSendFunction(connection).apply(1500);

        ArgumentCaptor<Long> argumentCaptor = ArgumentCaptor.forClass(Long.class);
        verify(flowController).increaseFlowControlLimit(any(QuicStreamImpl.class), argumentCaptor.capture()); //argThat(requestedLimit -> requestedLimit == 4));
        assertThat(argumentCaptor.getValue()).isEqualTo(4);
    }

    @Test
    void writeDataWillNotSendMoreThenFlowControlsAllows() throws Exception {
        // Given
        FlowControl flowController = mock(FlowControl.class);
        when(flowController.getFlowControlLimit(any(QuicStreamImpl.class))).thenReturn(100L);
        when(flowController.increaseFlowControlLimit(any(QuicStreamImpl.class), anyLong())).thenReturn(100L);

        QuicStreamImpl stream = new QuicStreamImpl(1, role, connection, streamManager, flowController);
        stream.getOutputStream().write(new byte[100]);

        StreamFrame frame = (StreamFrame) captureSendFunction(connection).apply(1500);
        assertThat(frame.getLength()).isLessThanOrEqualTo(100);
    }

    @Test
    void whenFlowControlLimitIsIncreasedMoreDataWillBeSent() throws Exception {
        // Given
        FlowControl flowController = new FlowControl(Role.Client, 100000, 100, 100, 100);
        ArgumentCaptor<FlowControlUpdateListener> fcUpdateListenerCaptor = ArgumentCaptor.forClass(FlowControlUpdateListener.class);

        QuicStreamImpl stream = new QuicStreamImpl(1, role, connection, streamManager, flowController);

        stream.getOutputStream().write(new byte[1024]);

        StreamFrame frame1 = (StreamFrame) captureSendFunction(connection).apply(1000);
        assertThat(frame1.getLength()).isLessThanOrEqualTo(100);
        StreamFrame noFrame = (StreamFrame) captureSendFunction(connection).apply(1000);

        // When
        flowController.process(new MaxStreamDataFrame(1, 233));

        // Then
        StreamFrame frame2 = (StreamFrame) captureSendFunction(connection, 2).apply(1000);
        assertThat(frame2.getLength()).isLessThanOrEqualTo(233);
    }
    //endregion

    //region output reset
    @Test
    void whenOutputIsResetWriteFails() {
        quicStream.resetStream(9);

        assertThatThrownBy(() ->
                quicStream.getOutputStream().write(new byte[10])
        ).isInstanceOf(IOException.class);
    }

    @Test
    void whenOutputIsResetNoStreamFrameIsSentAnymore() throws Exception {
        // Given
        quicStream.getOutputStream().write(new byte[10]);
        Function<Integer, QuicFrame> sendFunction = captureSendFunction(connection);

        // When
        quicStream.resetStream(9);

        // Then
        assertThat(sendFunction.apply(100)).isNull();
    }

    @Test
    void whenOutputIsResetThanResetStreamFrameIsSent() throws Exception {
        // Given
        int dataLength = 49 * 1024;
        quicStream.getOutputStream().write(new byte[dataLength]);
        Function<Integer, QuicFrame> sendFunction = captureSendFunction(connection);
        QuicFrame unused = sendFunction.apply(1000);
        captureSendFunction(connection);

        // When
        quicStream.resetStream(9);
        sendFunction = captureSendFunction(connection);

        // Then
        QuicFrame frame = sendFunction.apply(100);
        assertThat(frame).isInstanceOf(ResetStreamFrame.class);
        assertThat(((ResetStreamFrame) frame).getFinalSize()).isBetween(995L, 1005L);
    }

    @Test
    void whenOuputIsResetBlockingWriteIsAborted() throws Exception {
        // Given
        AtomicReference<Exception> thrownException = new AtomicReference<>();
        AtomicBoolean writeSucceeded = new AtomicBoolean(false);
        new Thread(() -> {
            try {
                quicStream.getOutputStream().write(new byte[1_000_000]);
                writeSucceeded.set(true);
            }
            catch (IOException e) {
                thrownException.set(e);
            }
        }).start();
        Thread.sleep(5);
        assertThat(writeSucceeded.get()).isFalse();

        // When
        quicStream.resetStream(9);

        // Then
        Thread.sleep(55);
        assertThat(thrownException.get())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("reset");
    }

    @Test
    void whenResetWriteShouldThrowException() throws Exception {
        // When
        quicStream.resetStream(9);

        // Then
        assertThatThrownBy(() ->
                quicStream.getOutputStream().write(new byte[10])
        ).isInstanceOf(IOException.class)
                .hasMessageContaining("stream is reset");
    }

    @Test
    void whenResetBlockedWriteShouldThrowException() throws Exception {
        // Given
        quicStream.getOutputStream().write(new byte[50 * 1024]);

        AtomicReference<Exception> thrownException = new AtomicReference<>();
        new Thread(() -> {
            try {
                quicStream.getOutputStream().write(new byte[10]);
            }
            catch (IOException e) {
                thrownException.set(e);
            }
        }).start();
        Thread.sleep(10);

        // When
        quicStream.resetStream(9);
        Thread.sleep(10);

        // Then
        assertThat(thrownException.get())
                .isInstanceOf(InterruptedIOException.class)  // Require InterruptedIOException, as that proofs the write was blocked before being interrupted.
                .hasMessageContaining("reset");
    }
    //endregion

    //region output abort
    @Test
    void writerDoesNotBlockWhenStreamAborted() throws Exception {
        // Given
        // Write as many bytes as the size of the send buffer, so a next write would block
        quicStream.getOutputStream().write(new byte[50 * 1024]);

        // When
        quicStream.abort();

        // Then
        // write() should not block and throw an exception to indicate that writing is not possible anymore
        Instant before = Instant.now();
        assertThatThrownBy(() ->
                quicStream.getOutputStream().write(new byte[10])
        ).isInstanceOf(IOException.class);
        Instant after = Instant.now();

        assertThat(Duration.between(before, after)).isLessThan(Duration.ofMillis(100));
    }

    @Test
    void blockingWriterIsInterruptedWhenStreamAborted() throws Exception {
        // Given
        // Write as many bytes as the size of the send buffer, so a next write will block
        quicStream.getOutputStream().write(new byte[50 * 1024]);

        AtomicBoolean writerHasThrownIOException = new AtomicBoolean(false);
        AtomicBoolean writerHasBeenBlocked = new AtomicBoolean(false);
        AtomicBoolean writerHasBeenUnblocked = new AtomicBoolean(false);
        ReentrantLock lock = new ReentrantLock();
        Condition threadHasStartedCondition = lock.newCondition();

        // When
        new Thread(() -> {
            lock.lock();
            threadHasStartedCondition.signal();
            lock.unlock();

            Instant before = Instant.now();
            try {
                quicStream.getOutputStream().write(new byte[1]);
            } catch (IOException e) {
                writerHasThrownIOException.set(true);
            }
            Instant after = Instant.now();
            writerHasBeenBlocked.set(Duration.between(before, after).toMillis() > 5);

            writerHasBeenUnblocked.set(true);
        }
        ).start();

        lock.lock();
        threadHasStartedCondition.await();
        lock.unlock();

        Thread.sleep(10);  // Give writer thread a change to start the write (and block)
        quicStream.abort();
        Thread.sleep(5);   // Give writer thread a change to awake from the wait

        // Then
        assertThat(writerHasBeenBlocked).isTrue();
        assertThat(writerHasBeenUnblocked).isTrue();
    }
    //endregion

    //region close
    @Test
    void whenEndOfStreamIsWrittenToUnidirectionalStreamItShouldBeClosed() throws IOException {
        // Given
        int streamId = 2;  // client initiated unidirectional stream
        quicStream = new QuicStreamImpl(streamId, Role.Client, connection, streamManager, mock(FlowControl.class));

        // When
        quicStream.getOutputStream().close();
        ((StreamOutputStreamImpl) quicStream.getOutputStream()).sendStreamFrame(1200);

        // Then
        verify(streamManager).streamClosed(eq(streamId));
    }

    @Test
    void whenAllIsReadFromUnidirectionalStreamItShouldBeClosed() throws Exception {
        // Given
        int streamId = 3;  // server initiated unidirectional stream
        quicStream = new QuicStreamImpl(streamId, Role.Client, connection, streamManager, mock(FlowControl.class));
        quicStream.addStreamData(new StreamFrame(streamId, new byte[10], true));

        // When
        quicStream.getInputStream().readAllBytes();

        // Then
        verify(streamManager).streamClosed(eq(streamId));
    }

    @Test
    void whenInputFromUnidirectionalIsClosedTheStreamShouldBeClosed() throws Exception {
        int streamId = 3;  // server initiated unidirectional stream
        quicStream = new QuicStreamImpl(streamId, Role.Client, connection, streamManager, mock(FlowControl.class));
        quicStream.addStreamData(new StreamFrame(streamId, new byte[10], true));

        // When
        quicStream.getInputStream().close();

        // Then
        verify(streamManager).streamClosed(eq(streamId));
    }

    @Test
    void whenServerHasReadAllFromClientInitiatedUnidirectionalStreamItShouldBeClosed() throws Exception {
        // Given
        role = Role.Server;
        int streamId = 2;  // client initiated unidirectional stream
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));
        quicStream.addStreamData(new StreamFrame(streamId, new byte[10], true));

        // When
        quicStream.getInputStream().readAllBytes();

        // Then
        verify(streamManager).streamClosed(eq(streamId));
    }

    @Test
    void whenServerHasReadAllFromAndWrittenAllToClientInitiatedBidirectionalStreamItShouldBeClosed() throws Exception {
        // Given
        role = Role.Server;
        int streamId = 0;  // client initiated bidirectional stream
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));
        quicStream.addStreamData(new StreamFrame(streamId, new byte[10], true));

        // When
        quicStream.getInputStream().readAllBytes();
        // And
        quicStream.getOutputStream().close();
        ((StreamOutputStreamImpl) quicStream.getOutputStream()).sendStreamFrame(1200);

        // Then
        verify(streamManager).streamClosed(eq(streamId));
    }

    @Test
    void whenServerHasReadAllFromButNotWrittenAllToClientInitiatedBidirectionalStreamItShouldNotBeClosed() throws Exception {
        // Given
        role = Role.Server;
        int streamId = 0;  // client initiated bidirectional stream
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));
        quicStream.addStreamData(new StreamFrame(streamId, new byte[10], true));

        // When
        quicStream.getInputStream().readAllBytes();
        quicStream.getOutputStream().write(new byte[10]);
        ((StreamOutputStreamImpl) quicStream.getOutputStream()).sendStreamFrame(1200);

        // Then
        verify(streamManager, never()).streamClosed(anyInt());
    }

    @Test
    void whenServerHasReadNotAllFromButWrittenAllToClientInitiatedBidirectionalStreamItShouldNotBeClosed() throws Exception {
        // Given
        role = Role.Server;
        int streamId = 0;  // client initiated bidirectional stream
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));
        quicStream.addStreamData(new StreamFrame(streamId, new byte[10], true));

        // When
        quicStream.getInputStream().read(new byte[3]);
        quicStream.getOutputStream().close();
        ((StreamOutputStreamImpl) quicStream.getOutputStream()).sendStreamFrame(1200);

        // Then
        verify(streamManager, never()).streamClosed(anyInt());
    }

    @Test
    void whenServerHasNeitherReadOrWrittenAllFromOrToClientInitiatedBidirectionalStreamItShouldNotBeClosed() throws Exception {
        // Given
        role = Role.Server;
        int streamId = 0;  // client initiated bidirectional stream
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));
        quicStream.addStreamData(new StreamFrame(streamId, new byte[10], true));

        // When
        quicStream.getInputStream().read(new byte[3]);
        quicStream.getOutputStream().write(new byte[10]);
        ((StreamOutputStreamImpl) quicStream.getOutputStream()).sendStreamFrame(1200);

        // Then
        verify(streamManager, never()).streamClosed(anyInt());
    }

    @Test
    void whenReceivingResetFrameForUnidirectionalClientInitiatedStreamClosedShouldBeCalled() throws Exception {
        // Given
        role = Role.Server;
        int streamId = 2;  // client initiated unidirectional stream
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));

        // When
        quicStream.terminateStream(9, 49493);

        // Then
        verify(streamManager).streamClosed(eq(quicStream.streamId));
    }

    @Test
    void whenSendingResetFrameClosedShouldBeCalled() throws Exception {
        // Given
        role = Role.Server;
        int streamId = 3;  // server initiated unidirectional stream
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));

        // When
        quicStream.resetStream(9);

        // Then
        verify(streamManager).streamClosed(eq(quicStream.streamId));
    }

    @Test
    void closeAfterAbortShouldNotLeadToFrameBeingSent() throws Exception {
        // Given
        role = Role.Server;
        int streamId = 3;  // server initiated unidirectional stream
        quicStream = new QuicStreamImpl(streamId, role, connection, streamManager, mock(FlowControl.class));
        quicStream.abort();

        // When
        quicStream.getOutputStream().close();

        // Then
        verify(connection, never()).send(any(Function.class), anyInt(), any(EncryptionLevel.class), any(Consumer.class), anyBoolean());
    }
    //endregion

    //region retransmissions
    @Test
    void lostStreamFrameShouldBeRetransmitted() throws Exception {
        ArgumentCaptor<Consumer> lostFrameCallbackCaptor = ArgumentCaptor.forClass(Consumer.class);
        ArgumentCaptor<Function<Integer, QuicFrame>> sendFunctionCaptor = ArgumentCaptor.forClass(Function.class);

        quicStream.getOutputStream().write("this frame might get lost".getBytes());
        verify(connection, times(1)).send(sendFunctionCaptor.capture(), anyInt(), any(EncryptionLevel.class), lostFrameCallbackCaptor.capture(), anyBoolean());

        QuicFrame lostFrame = sendFunctionCaptor.getValue().apply(1500);
        Consumer lostFrameCallback = lostFrameCallbackCaptor.getValue();

        // When the recovery manager determines that the frame is lost, it will call the lost-frame-callback with the lost frame as argument
        lostFrameCallback.accept(lostFrame);

        ArgumentCaptor<Function<Integer, QuicFrame>>  retransmitFunction= ArgumentCaptor.forClass(Function.class);

        verify(connection, atLeastOnce()).send(retransmitFunction.capture(), anyInt(), any(EncryptionLevel.class), any(Consumer.class), anyBoolean());

        QuicFrame retransmittedFrame = retransmitFunction.getValue().apply(1500);

        assertThat(retransmittedFrame).isInstanceOf(StreamFrame.class);
        assertThat(retransmittedFrame).isEqualTo(lostFrame);
    }

    @Test
    void lostMaxStreamDataFrameShouldBeResentWithActualValues() throws Exception {
        float factor = StreamInputStreamImpl.receiverMaxDataIncrementFactor;
        int initialWindow = 1000;
        when(streamManager.getMaxBidirectionalStreamBufferSize()).thenReturn((long) initialWindow);
        when(streamManager.getMaxUnidirectionalStreamBufferSize()).thenReturn((long) initialWindow);

        quicStream = new QuicStreamImpl(0, role, connection, streamManager, mock(FlowControl.class), logger);  // Re-instantiate because constructor reads initial max stream data from connection
        quicStream.addStreamData(resurrect(new StreamFrame(0, new byte[1000], true)));

        InputStream inputStream = quicStream.getInputStream();
        inputStream.read(new byte[(int) (initialWindow * factor + 1)]);

        ArgumentCaptor<Consumer> lostFrameCallbackCaptor = ArgumentCaptor.forClass(Consumer.class);
        ArgumentCaptor<QuicFrame> sendFrameCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(connection, times(1)).send(sendFrameCaptor.capture(), lostFrameCallbackCaptor.capture(), anyBoolean());
        MaxStreamDataFrame lostFrame = (MaxStreamDataFrame) sendFrameCaptor.getValue();
        clearInvocations(connection);

        // Advance flow control window (but not so much a new MaxStreamDataFrame is sent...)
        inputStream.read(new byte[(int) (initialWindow * factor / 2)]);

        // When the recovery manager determines that the frame is lost, it will call the lost-frame-callback with the lost frame as argument
        lostFrameCallbackCaptor.getValue().accept(lostFrame);

        ArgumentCaptor<QuicFrame> resendFrameCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(connection, times(1)).send(resendFrameCaptor.capture(), any(Consumer.class));

        MaxStreamDataFrame retransmittedFrame = (MaxStreamDataFrame) resendFrameCaptor.getValue();
        assertThat(retransmittedFrame).isInstanceOf(MaxStreamDataFrame.class);
        assertThat(retransmittedFrame.getMaxData()).isGreaterThanOrEqualTo(lostFrame.getMaxData() + (int) (initialWindow * factor / 2));
    }

    @Test
    void lostFinalFrameShouldBeRetransmitted() throws Exception {
        ArgumentCaptor<Function<Integer, QuicFrame>> sendFunctionCaptor = ArgumentCaptor.forClass(Function.class);

        quicStream.getOutputStream().write("just a stream frame".getBytes());
        verify(connection, times(1)).send(sendFunctionCaptor.capture(), anyInt(), any(EncryptionLevel.class), any(Consumer.class), anyBoolean());
        clearInvocations(connection);
        // Simulate data is sent (will call QuicStream::sendFrame)
        QuicFrame frame = sendFunctionCaptor.getValue().apply(1500);
        // Should not call send again, as there is (currently) nothing more to send.
        verify(connection, never()).send(any(Function.class), anyInt(), any(EncryptionLevel.class), any(Consumer.class));
        clearInvocations(connection);

        quicStream.getOutputStream().close();  // Close will send an empty final frame.

        ArgumentCaptor<Function<Integer, QuicFrame>> sendFunctionCaptor2 = ArgumentCaptor.forClass(Function.class);
        ArgumentCaptor<Consumer> lostFrameCallbackCaptor = ArgumentCaptor.forClass(Consumer.class);
        verify(connection, times(1)).send(sendFunctionCaptor2.capture(), anyInt(), any(EncryptionLevel.class), lostFrameCallbackCaptor.capture(), anyBoolean());
        clearInvocations(connection);
        // Simulate close frame is actually sent
        QuicFrame frameThatWillBecomeLost = sendFunctionCaptor2.getValue().apply(1500);
        // Should not call send again, as there is (currently) nothing more to send.
        verify(connection, never()).send(any(Function.class), anyInt(), any(EncryptionLevel.class), any(Consumer.class));
        clearInvocations(connection);

        Consumer lostFrameCallback = lostFrameCallbackCaptor.getValue();

        // When the recovery manager determines that the frame is lost, it will call the lost-frame-callback with the lost frame as argument
        lostFrameCallback.accept(frameThatWillBecomeLost);

        ArgumentCaptor<Function<Integer, QuicFrame>>  retransmitFunction= ArgumentCaptor.forClass(Function.class);

        verify(connection, atLeastOnce()).send(retransmitFunction.capture(), anyInt(), any(EncryptionLevel.class), any(Consumer.class), anyBoolean());

        QuicFrame retransmittedFrame = retransmitFunction.getValue().apply(1500);

        assertThat(retransmittedFrame).isInstanceOf(StreamFrame.class);
        assertThat(((StreamFrame) retransmittedFrame).isFinal()).isTrue();
    }
    //endregion

    // region test helper methods
    private byte[] generateByteArray(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            // Generate abc...z sequence; ASCII A = 97
            data[i] = (byte) (97 + (i % 26));
        }
        return data;
    }

    /**
     * Serializes the given frame and parses the result, to simulate receiving a frame.
     * This is necessary because not all fields off a parsed frame are available in a constructed frame, e.g. StreamFrame.applicationData.
     * @param streamFrame
     * @return the resurrected frame
     */
    private StreamFrame resurrect(StreamFrame streamFrame) {
        try {
            ByteBuffer buffer = ByteBuffer.allocate(25 + streamFrame.getLength());
            streamFrame.serialize(buffer);
            buffer.flip();
            return new StreamFrame().parse(buffer, logger);
        }
        catch (InvalidIntegerEncodingException | TransportError | IntegerTooLargeException e) {
            throw new RuntimeException(e);
        }
    }

    private Function<Integer, QuicFrame> captureSendFunction(QuicConnectionImpl connection) {
        return captureSendFunction(connection, 1);
    }

    private Function<Integer, QuicFrame> captureSendFunction(QuicConnectionImpl connection, int expectedInvocations) {
        ArgumentCaptor<Function<Integer, QuicFrame>> captor = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(expectedInvocations)).send(captor.capture(), anyInt(), argThat(l -> l == EncryptionLevel.App), any(Consumer.class), anyBoolean());
        clearInvocations(connection);
        return captor.getValue();
    }

    /**
     * Mockito Argumentmatcher for checking StreamFrame arguments.
     */
    private class StreamFrameMatcher implements ArgumentMatcher<StreamFrame> {

        private final byte[] expectedBytes;
        private final int expectedOffset;
        private final boolean expectedFinalFlag;

        public StreamFrameMatcher(byte[] bytes) {
            expectedBytes = bytes;
            expectedOffset = 0;
            expectedFinalFlag = false;
        }

        public StreamFrameMatcher(byte[] bytes, int offset) {
            expectedBytes = bytes;
            expectedOffset = offset;
            expectedFinalFlag = false;
        }

        public StreamFrameMatcher(byte[] bytes, int offset, boolean fin) {
            expectedOffset = offset;
            expectedBytes = bytes;
            expectedFinalFlag = fin;
        }

        @Override
        public boolean matches(StreamFrame streamFrame) {
            streamFrame = resurrect(streamFrame);
            return Arrays.equals(streamFrame.getStreamData(), expectedBytes)
                    && streamFrame.getOffset() == expectedOffset
                    && streamFrame.isFinal() == expectedFinalFlag;
        }
    }

    /**
     * Mockito Argumentmatcher for checking StreamFrame arguments on data length.
     */
    private class StreamFrameDataLengthMatcher implements ArgumentMatcher<StreamFrame> {

            private final int expectedLength;

            public StreamFrameDataLengthMatcher(int length) {
                expectedLength = length;
            }

        @Override
        public boolean matches(StreamFrame streamFrame) {
            return streamFrame.getLength() == expectedLength;
        }
    }
    // endregion
}