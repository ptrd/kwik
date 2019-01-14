/*
 * Copyright © 2019 Peter Doornbosch
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
package net.luminis.quic;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;


class QuicStreamTest {

    private static long originalWaitForNextFrameTimeoutValue;
    private QuicConnection connection;
    private Logger logger;

    @BeforeAll
    static void setFiniteWaitForNextFrameTimeout() {
        originalWaitForNextFrameTimeoutValue = QuicStream.waitForNextFrameTimeout;
        QuicStream.waitForNextFrameTimeout = 1;
    }

    @AfterAll
    static void resetWaitForNextFrameTimeout() {
        QuicStream.waitForNextFrameTimeout = originalWaitForNextFrameTimeoutValue;
    }

    @BeforeEach
    void createDefaultMocks() {
        connection = Mockito.mock(QuicConnection.class);
        when(connection.getMaxPacketSize()).thenReturn(1232);
        logger = Mockito.mock(Logger.class);
    }

    @Test
    void testReadSingleFinalStreamFrame() throws IOException {
        connection = Mockito.mock(QuicConnection.class);
        QuicStream quicStream = new QuicStream(0, connection, logger);

        quicStream.add(resurrect(new StreamFrame(0, "data".getBytes(), true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("data".getBytes());
    }

    @Test
    public void testReadMultipleStreamFrames() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);

        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 6, "second-final".getBytes(), true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-final".getBytes());
    }

    @Test
    void testAddDuplicateStreamFrames() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);

        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 6, "second-final".getBytes(), true)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-final".getBytes());
    }

    @Test
    void testAddNonContiguousStreamFrames() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);

        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 13, "third-final".getBytes(), true)));
        quicStream.add(resurrect(new StreamFrame(0, 6, "second-".getBytes(), false)));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-third-final".getBytes());
    }

    @Test
    void testReadBlocksTillContiguousFrameIsAvailalble() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);

        quicStream.add(resurrect(new StreamFrame(0, "first-".getBytes(), false)));
        quicStream.add(resurrect(new StreamFrame(0, 13, "third-final".getBytes(), true)));

        byte[] buffer = new byte[100];
        int initialReadCount = quicStream.getInputStream().read(buffer);

        try {
            quicStream.getInputStream().read(buffer, initialReadCount, buffer.length - initialReadCount);

            // It should not get here
            fail("read method should not succesfully return");
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
    void testStreamOutputWithByteArray() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);
        quicStream.getOutputStream().write("hello world".getBytes());

        verify(connection, times(1)).send(argThat(new StreamFrameMatcher("hello world".getBytes())));
    }

    @Test
    void testStreamOutputWithByteArrayFragment() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);
        quicStream.getOutputStream().write(">> hello world <<".getBytes(), 3, 11);

        verify(connection, times(1)).send(argThat(new StreamFrameMatcher("hello world".getBytes())));
    }

    @Test
    void testStreamOutputWithSingleByte() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);
        quicStream.getOutputStream().write(0x23);  // ASCII 23 == '#'

        verify(connection, times(1)).send(argThat(new StreamFrameMatcher("#".getBytes())));
    }

    @Test
    void testStreamOutputMultipleFrames() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);
        quicStream.getOutputStream().write("hello ".getBytes());
        quicStream.getOutputStream().write("world".getBytes());

        verify(connection, times(1)).send(argThat(new StreamFrameMatcher("hello ".getBytes())));
        verify(connection, times(1)).send(argThat(new StreamFrameMatcher("world".getBytes(), 6)));
    }

    @Test
    void testCloseSendsFinalFrame() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);
        quicStream.getOutputStream().write("hello world!".getBytes());
        quicStream.getOutputStream().close();

        verify(connection, times(1)).send(argThat(new StreamFrameMatcher(new byte[0], 12, true)));
    }

    @Test
    void testOutputWithByteArrayLargerThanMaxPacketSizeIsSplitOverMultiplePackets() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);
        byte[] data = generateByteArray(1400);
        quicStream.getOutputStream().write(data);

        ArgumentCaptor<StreamFrame> captor = ArgumentCaptor.forClass(StreamFrame.class);
        verify(connection, times(2)).send(captor.capture());
        // This is what the test is about: the first frame should be less than max packet size.
        int lengthFirstFrame = captor.getAllValues().get(0).getLength();
        assertThat(lengthFirstFrame).isLessThan(1300);
        // And of course, the remaining bytes should be in the second frame.
        int totalFrameLength = captor.getAllValues().stream().mapToInt(f -> f.getLength()).sum();
        assertThat(totalFrameLength).isEqualTo(1400);

        // Also, the content should be copied correctly over the two frames:
        StreamFrame firstFrame = resurrect(captor.getAllValues().get(0));
        StreamFrame secondFrame = resurrect(captor.getAllValues().get(1));
        byte[] reconstructedContent = new byte[firstFrame.getStreamData().length + secondFrame.getStreamData().length];
        System.arraycopy(firstFrame.getStreamData(), 0, reconstructedContent, 0, firstFrame.getStreamData().length);
        System.arraycopy(secondFrame.getStreamData(), 0, reconstructedContent, firstFrame.getStreamData().length, secondFrame.getStreamData().length);
        assertThat(reconstructedContent).isEqualTo(data);
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
        return new StreamFrame().parse(ByteBuffer.wrap(streamFrame.getBytes()), logger);
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
}