/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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

import net.luminis.quic.*;
import net.luminis.quic.frame.MaxStreamDataFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatcher;
import org.mockito.InOrder;
import org.mockito.Mockito;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;


class QuicStreamTest {

    private static long originalWaitForNextFrameTimeoutValue;
    private QuicConnectionImpl connection;
    private QuicStream quicStream;
    private Logger logger;
    private Random randomGenerator = new Random();

    @BeforeAll
    static void setFiniteWaitForNextFrameTimeout() {
        setFiniteWaitForNextFrameTimeout(5);
    }

    @AfterAll
    static void resetWaitForNextFrameTimeout() {
        QuicStream.waitForNextFrameTimeout = originalWaitForNextFrameTimeoutValue;
    }

    @BeforeEach
    void createDefaultMocksAndObjectUnderTest() {
        connection = Mockito.mock(QuicConnectionImpl.class);
        logger = Mockito.mock(Logger.class);

        quicStream = new QuicStream(0, connection, new FlowControl(Role.Client, 9999, 9999, 9999, 9999), logger);
    }

    @Test
    void testReadSingleFinalStreamFrame() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "data".getBytes(), true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("data".getBytes());
    }

    @Test
    void testReadStreamWithNonAsciiBytes() throws IOException {
        byte[] data = {
                0x00, 0x01, 0x02, (byte) 0xff, (byte) 0xfe, (byte) 0xfd
        };
        quicStream.add(resurrect(new StreamFrame(0, data, true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo(data);
    }

    @Test
    void testReadStreamWithFFByte() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, new byte[] { (byte) 0xff }, true)));

        assertThat(quicStream.getInputStream().read()).isEqualTo(0xff);
    }

    @Test
    void testAvailableBytesForSingleFrame() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "data".getBytes(), true)));

        assertThat(quicStream.getInputStream().available()).isEqualTo(4);
    }

    @Test
    void testAvailableBytesForSingleFrameAfterRead() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "data".getBytes(), true)));
        InputStream inputStream = quicStream.getInputStream();
        inputStream.read();

        assertThat(inputStream.available()).isEqualTo(3);
    }

    @Test
    void testAvailableAfterReadingAllAvailable() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "data".getBytes(), false)));
        InputStream inputStream = quicStream.getInputStream();
        inputStream.read(new byte[4]);

        assertThat(inputStream.available()).isEqualTo(0);
    }

    @Test
    public void testReadMultipleStreamFrames() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 6, "second-final".getBytes(), true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-final".getBytes());
    }

    @Test
    public void testAvailableWithMultipleStreamFrames() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 6, "second-final".getBytes(), true)));

        assertThat(quicStream.getInputStream().available()).isGreaterThan("first-".getBytes().length - 1);
    }

    @Test
    public void testAvailableAfterReadingFirstFrame() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 6, "second-final".getBytes(), true)));

        InputStream inputStream = quicStream.getInputStream();
        assertThat(inputStream.available()).isGreaterThan("first-".getBytes().length - 1);

        inputStream.read(new byte["first-".getBytes().length]);
        assertThat(inputStream.available()).isEqualTo("second-final".getBytes().length);
    }

    @Test
    void testAddDuplicateStreamFrames() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 6, "second-final".getBytes(), true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-final".getBytes());
    }

    @Test
    void testAddNonContiguousStreamFrames() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 13, "third-final".getBytes(), true)));
        quicStream.add(resurrect(new StreamFrame(0, 6, "second-".getBytes(), false)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-third-final".getBytes());
    }

    @Test
    void testAddMultipleOutOfOrderFrames() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 13, "third-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 19, "forth-final".getBytes(), true)));
        quicStream.add(resurrect(new StreamFrame(0, 6, "second-".getBytes(), false)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-third-forth-final".getBytes());
    }

    @Test
    void testAddInterleavedOutOfOrderFrames() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 13, "third-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 6, "second-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 19, "forth-final".getBytes(), true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-third-forth-final".getBytes());
    }

    @Test
    void testReadBlocksTillContiguousFrameIsAvailalble() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 13, "third-final".getBytes(), true)));

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
            quicStream.add(resurrect(new StreamFrame(0, 6, "second-".getBytes(), false)));

            // Read more
            int lastRead = quicStream.getInputStream().read(buffer, initialReadCount, buffer.length - initialReadCount);
            assertThat(buffer).startsWith("first-second-third-final".getBytes());
            assertThat(initialReadCount + lastRead).isEqualTo("first-second-third-final".getBytes().length);
        }
    }

    @Test
    void testReadAtEndOfStreamReturns() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "1".getBytes(), true)));
        InputStream inputStream = quicStream.getInputStream();

        assertThat(inputStream.read()).isEqualTo(49);
        assertThat(inputStream.read()).isEqualTo(-1);
        assertThat(inputStream.read()).isEqualTo(-1);
    }

    @Test
    void testAvailableAtEndOfStreamReturnsZero() throws IOException {
        quicStream.add(resurrect(new StreamFrame(0, "1".getBytes(), true)));
        InputStream inputStream = quicStream.getInputStream();

        assertThat(inputStream.read()).isEqualTo(49);
        assertThat(inputStream.read()).isEqualTo(-1);
        assertThat(inputStream.available()).isEqualTo(0);
        assertThat(inputStream.read()).isEqualTo(-1);  // Important: read() must keep on returning -1!
    }

    @Test
    void testStreamOutputWithByteArray() throws IOException {
        // Given
        quicStream.getOutputStream().write("hello world".getBytes());

        // When
        QuicFrame streamFrame = captureSendFunction(connection).apply(1500);

        // Then
        assertThat(((StreamFrame) streamFrame).getStreamData()).isEqualTo("hello world".getBytes());
    }

    @Test
    void testStreamOutputWithByteArrayFragment() throws IOException {
        // Given
        quicStream.getOutputStream().write(">> hello world <<".getBytes(), 3, 11);

        // When
        QuicFrame streamFrame = captureSendFunction(connection).apply(1500);

        // Then
        assertThat(((StreamFrame) streamFrame).getStreamData()).isEqualTo("hello world".getBytes());
    }

    @Test
    void testStreamOutputWithSingleByte() throws IOException {
        // Given
        quicStream.getOutputStream().write(0x23);  // ASCII 23 == '#'

        // When
        QuicFrame streamFrame = captureSendFunction(connection).apply(1500);

        // Then
        assertThat(((StreamFrame) streamFrame).getStreamData()).isEqualTo("#".getBytes());
    }

    @Test
    void testStreamOutputMultipleFrames() throws IOException {
        // Given
        quicStream.getOutputStream().write("hello ".getBytes());
        quicStream.getOutputStream().write("world".getBytes());

        // When
        QuicFrame streamFrame = captureSendFunction(connection).apply(1500);

        // Then
        assertThat(((StreamFrame) streamFrame).getStreamData()).isEqualTo("hello world".getBytes());
    }

    @Test
    void testCloseSendsFinalFrame() throws IOException {
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
    void testOutputWithByteArrayLargerThanMaxPacketSizeIsSplitOverMultiplePackets() throws IOException {
        byte[] data = generateByteArray(1700);
        quicStream.getOutputStream().write(data);

        ArgumentCaptor<Function<Integer, QuicFrame>> captor = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(captor.capture(), anyInt(), argThat(l -> l == EncryptionLevel.App), any(Consumer.class), anyBoolean());

        StreamFrame firstFrame = (StreamFrame) captor.getAllValues().get(0).apply(1200);
        verify(connection, times(2)).send(captor.capture(), anyInt(), argThat(l -> l == EncryptionLevel.App), any(Consumer.class), anyBoolean());
        StreamFrame secondFrame = (StreamFrame) captor.getAllValues().get(1).apply(1200);

        // This is what the test is about: the first frame should be less than max packet size.
        assertThat(firstFrame.getBytes().length).isLessThanOrEqualTo(1200);
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
    void testStreamFlowControlUpdates() throws IOException {
        float factor = QuicStream.receiverMaxDataIncrementFactor;
        int initialWindow = 1000;
        when(connection.getInitialMaxStreamData()).thenReturn((long) initialWindow);

        quicStream = new QuicStream(0, connection, mock(FlowControl.class), logger);  // Re-instantiate because constructor reads initial max stream data from connection

        quicStream.add(resurrect(new StreamFrame(0, new byte[10000], true)));
        InputStream inputStream = quicStream.getInputStream();

        inputStream.read(new byte[(int) (initialWindow * factor * 0.8)]);
        verify(connection, never()).send(any(QuicFrame.class), any(Consumer.class));

        inputStream.read(new byte[(int) (initialWindow * factor * 0.2 - 1)]);
        verify(connection, never()).send(any(QuicFrame.class), any(Consumer.class));

        inputStream.read(new byte[2]);
        verify(connection, times(1)).send(any(MaxStreamDataFrame.class), any(Consumer.class));

        inputStream.read(new byte[(int) (initialWindow * factor)]);
        verify(connection, times(1)).send(any(MaxStreamDataFrame.class), any(Consumer.class));

        inputStream.read(new byte[2]);
        verify(connection, times(2)).send(any(MaxStreamDataFrame.class), any(Consumer.class));

        clearInvocations();
        inputStream.read(new byte[(int) (initialWindow * factor * 3.1)]);
        verify(connection, times(3)).send(any(MaxStreamDataFrame.class), any(Consumer.class));
    }

    @Test
    void noMoreFlowControlCreditsShouldBeRequestedThanByteCountInBuffer() throws Exception {
        FlowControl flowController = mock(FlowControl.class);
        when(flowController.getFlowControlLimit(any(QuicStream.class))).thenReturn(1500L);
        quicStream = new QuicStream(0, connection, flowController, logger);  // Re-instantiate to access to flow control object
        quicStream.getOutputStream().write(new byte[] { (byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe });

        // When
        QuicFrame streamFrame = captureSendFunction(connection).apply(1500);

        ArgumentCaptor<Long> argumentCaptor = ArgumentCaptor.forClass(Long.class);
        verify(flowController).increaseFlowControlLimit(any(QuicStream.class), argumentCaptor.capture()); //argThat(requestedLimit -> requestedLimit == 4));
        assertThat(argumentCaptor.getValue()).isEqualTo(4);
    }

    @Test
    void lostStreamFrameShouldBeRetransmitted() throws IOException {
        ArgumentCaptor<Consumer> lostFrameCallbackCaptor = ArgumentCaptor.forClass(Consumer.class);
        ArgumentCaptor<Function<Integer, QuicFrame>> sendFunctionCaptor = ArgumentCaptor.forClass(Function.class);

        quicStream.getOutputStream().write("this frame might get lost".getBytes());
        verify(connection, times(1)).send(sendFunctionCaptor.capture(), anyInt(), any(EncryptionLevel.class), lostFrameCallbackCaptor.capture(), anyBoolean());

        QuicFrame lostFrame = sendFunctionCaptor.getValue().apply(1500);
        Consumer lostFrameCallback = lostFrameCallbackCaptor.getValue();

        // When the recovery manager determines that the frame is lost, it will call the lost-frame-callback with the lost frame as argument
        lostFrameCallback.accept(lostFrame);

        ArgumentCaptor<QuicFrame> retransmittedFrameCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        ArgumentCaptor<Consumer> lostRetransmittedFrameCallbackCaptor = ArgumentCaptor.forClass(Consumer.class);

        verify(connection, atLeastOnce()).send(retransmittedFrameCaptor.capture(), lostRetransmittedFrameCallbackCaptor.capture(), anyBoolean());

        QuicFrame retransmittedFrame = retransmittedFrameCaptor.getValue();

        assertThat(retransmittedFrame).isInstanceOf(StreamFrame.class);
        assertThat(retransmittedFrame).isEqualTo(lostFrame);
    }

    @Test
    void lostMaxStreamDataFrameShouldBeResentWithActualValues() throws IOException {
        float factor = QuicStream.receiverMaxDataIncrementFactor;
        int initialWindow = 1000;
        when(connection.getInitialMaxStreamData()).thenReturn((long) initialWindow);

        quicStream = new QuicStream(0, connection, mock(FlowControl.class), logger);  // Re-instantiate because constructor reads initial max stream data from connection
        quicStream.add(resurrect(new StreamFrame(0, new byte[10000], true)));

        InputStream inputStream = quicStream.getInputStream();
        inputStream.read(new byte[(int) (initialWindow * factor + 1)]);

        ArgumentCaptor<Consumer> lostFrameCallbackCaptor = ArgumentCaptor.forClass(Consumer.class);
        ArgumentCaptor<QuicFrame> sendFrameCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(connection, times(1)).send(sendFrameCaptor.capture(), lostFrameCallbackCaptor.capture());
        MaxStreamDataFrame lostFrame = (MaxStreamDataFrame) sendFrameCaptor.getValue();

        // Advance flow control window (but not so much a new MaxStreamDataFrame is sent...)
        inputStream.read(new byte[(int) (initialWindow * factor / 2)]);

        // When the recovery manager determines that the frame is lost, it will call the lost-frame-callback with the lost frame as argument
        lostFrameCallbackCaptor.getValue().accept(lostFrame);

        ArgumentCaptor<QuicFrame> resendFrameCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(connection, times(2)).send(resendFrameCaptor.capture(), any(Consumer.class));

        MaxStreamDataFrame retransmittedFrame = (MaxStreamDataFrame) resendFrameCaptor.getValue();
        assertThat(retransmittedFrame).isInstanceOf(MaxStreamDataFrame.class);
        assertThat(retransmittedFrame.getMaxData()).isGreaterThanOrEqualTo(lostFrame.getMaxData() + (int) (initialWindow * factor / 2));
    }

    @Test
    void lostFinalFrameShouldBeRetransmitted() throws IOException {
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

        ArgumentCaptor<QuicFrame> retransmittedFrameCaptor = ArgumentCaptor.forClass(QuicFrame.class);
        ArgumentCaptor<Consumer> lostRetransmittedFrameCallbackCaptor = ArgumentCaptor.forClass(Consumer.class);

        verify(connection, times(1)).send(retransmittedFrameCaptor.capture(), lostRetransmittedFrameCallbackCaptor.capture(), anyBoolean());

        QuicFrame retransmittedFrame = retransmittedFrameCaptor.getValue();

        assertThat(retransmittedFrame).isInstanceOf(StreamFrame.class);
        assertThat(((StreamFrame) retransmittedFrame).isFinal()).isTrue();
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
        quicStream = new QuicStream(Version.getDefault(), 0, connection,
                new FlowControl(Role.Client, 9999, 9999, 9999, 9999),
                logger, 77);
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

        ByteBuffer dataSent = ByteBuffer.allocate(1000);
        StreamFrame lastFrame = null;
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
    void isUnidirectional() {
        QuicStream clientInitiatedStream = new QuicStream(2, mock(QuicConnectionImpl.class), mock(FlowControl.class));
        assertThat(clientInitiatedStream.isUnidirectional()).isTrue();

        QuicStream serverInitiatedStream = new QuicStream(3, mock(QuicConnectionImpl.class), mock(FlowControl.class));
        assertThat(serverInitiatedStream.isUnidirectional()).isTrue();
    }

    @Test
    void isClientInitiatedBidirectional() {
        QuicStream stream = new QuicStream(0, mock(QuicConnectionImpl.class), mock(FlowControl.class));
        assertThat(stream.isClientInitiatedBidirectional()).isTrue();
    }

    @Test
    void isServerInitiatedBidirectional() {
        QuicStream stream = new QuicStream(1, mock(QuicConnectionImpl.class), mock(FlowControl.class));
        assertThat(stream.isServerInitiatedBidirectional()).isTrue();
    }

    @Test
    void writeDataWillNotSendMoreThenFlowControlsAllows() throws Exception {
        // Given
        FlowControl flowController = mock(FlowControl.class);
        when(flowController.getFlowControlLimit(any(QuicStream.class))).thenReturn(100L);
        when(flowController.increaseFlowControlLimit(any(QuicStream.class), anyLong())).thenReturn(100L);

        QuicStream stream = new QuicStream(1, connection, flowController);
        stream.getOutputStream().write(new byte[100]);

        StreamFrame frame = (StreamFrame) captureSendFunction(connection).apply(1500);
        assertThat(frame.getLength()).isLessThanOrEqualTo(100);
    }

    @Test
    void whenFlowControlLimitIsIncreasedMoreDataWillBeSent() throws Exception {
        // Given
        FlowControl flowController = new FlowControl(Role.Client, 100000, 100, 100, 100);
        ArgumentCaptor<FlowControlUpdateListener> fcUpdateListenerCaptor = ArgumentCaptor.forClass(FlowControlUpdateListener.class);

        QuicStream stream = new QuicStream(1, connection, flowController);

        stream.getOutputStream().write(new byte[1024]);

        StreamFrame frame1 = (StreamFrame) captureSendFunction(connection).apply(1000);
        assertThat(frame1.getLength()).isLessThanOrEqualTo(100);
        StreamFrame noFrame = (StreamFrame) captureSendFunction(connection).apply(1000);

        // When
        flowController.process(new MaxStreamDataFrame(1, 233));

        // Then
        StreamFrame frame2 = (StreamFrame) captureSendFunction(connection).apply(1000);
        assertThat(frame2.getLength()).isLessThanOrEqualTo(233);
    }

    @Test
    void readReturnsMinusOneWhenEndOfStreamIsReached() {
        // Given
        quicStream.add(new StreamFrame(9, new byte[10], true));
        ByteBuffer buffer = ByteBuffer.allocate(50);

        // When
        int read = quicStream.read(buffer);
        assertThat(read).isEqualTo(10);

        // Then
        read = quicStream.read(buffer);
        assertThat(read).isEqualTo(-1);
    }

    @Test
    void availableReturnsNegativeWhenEndOfStreamIsReached() {
        // Given
        quicStream.add(new StreamFrame(9, new byte[10], true));
        ByteBuffer buffer = ByteBuffer.allocate(50);

        // When
        int read = quicStream.read(buffer);
        assertThat(read).isEqualTo(10);

        // Then
        int available = quicStream.bytesAvailable();
        assertThat(available).isEqualTo(-1);
    }

    @Test
    void receivingEmptyLastFrameTerminatesBlockingRead() throws Exception {
        setFiniteWaitForNextFrameTimeout(25);       // Make long enough to have reader thread blocking when new frame arrives
        // Given
        InputStream inputStream = quicStream.getInputStream();
        quicStream.add(resurrect(new StreamFrame(0, "data".getBytes(), false)));
        int firstRead = inputStream.read(new byte[100]);

        // When
        // Async add of stream frame while read is already blocking
        new Thread(() -> {
            try {
                Thread.sleep(5);   // Wait long enough to have reader thread block, but not to long to cause wait timeout
            } catch (InterruptedException e) {}
            quicStream.add(resurrect(new StreamFrame(0, 4, new byte[0], true)));
        }).start();

        int secondRead = inputStream.read(new byte[100]);

        // Then
        assertThat(firstRead).isEqualTo(4);
        assertThat(secondRead).isEqualTo(-1);
    }

    static private void setFiniteWaitForNextFrameTimeout(int timeout) {
        originalWaitForNextFrameTimeoutValue = QuicStream.waitForNextFrameTimeout;
        QuicStream.waitForNextFrameTimeout = timeout;
    }

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
            return new StreamFrame().parse(ByteBuffer.wrap(streamFrame.getBytes()), logger);
        } catch (InvalidIntegerEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private Function<Integer, QuicFrame> captureSendFunction(QuicConnectionImpl connection) {
        ArgumentCaptor<Function<Integer, QuicFrame>> captor = ArgumentCaptor.forClass(Function.class);
        verify(connection, times(1)).send(captor.capture(), anyInt(), argThat(l -> l == EncryptionLevel.App), any(Consumer.class), anyBoolean());
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

}