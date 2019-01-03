package net.luminis.quic;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.AdditionalMatchers.or;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;


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
        logger = Mockito.mock(Logger.class);
    }

    @Test
    void testReadSingleFinalStreamFrame() throws IOException {
        connection = Mockito.mock(QuicConnection.class);
        QuicStream quicStream = new QuicStream(0, connection, logger);

        quicStream.add(new StreamFrame(0, "data".getBytes(), true));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("data".getBytes());
    }

    @Test
    public void testReadMultipleStreamFrames() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);

        quicStream.add(new StreamFrame(0, "first-".getBytes(), false));
        quicStream.add(new StreamFrame(0, 6, "second-final".getBytes(), true));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-final".getBytes());
    }

    @Test
    void testAddDuplicateStreamFrames() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);

        quicStream.add(new StreamFrame(0, "first-".getBytes(), false));
        quicStream.add(new StreamFrame(0, "first-".getBytes(), false));
        quicStream.add(new StreamFrame(0, 6, "second-final".getBytes(), true));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-final".getBytes());
    }

    @Test
    void testAddNonContiguousStreamFrames() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);

        quicStream.add(new StreamFrame(0, "first-".getBytes(), false));
        quicStream.add(new StreamFrame(0, 13, "third-final".getBytes(), true));
        quicStream.add(new StreamFrame(0, 6, "second-".getBytes(), false));

        assertThat(quicStream.getInputStream().readAllBytes()).isEqualTo("first-second-third-final".getBytes());
    }

    @Test
    void testReadBlocksTillContiguousFrameIsAvailalble() throws IOException {
        QuicStream quicStream = new QuicStream(0, connection, logger);

        quicStream.add(new StreamFrame(0, "first-".getBytes(), false));
        quicStream.add(new StreamFrame(0, 13, "third-final".getBytes(), true));

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
            quicStream.add(new StreamFrame(0, 6, "second-".getBytes(), false));

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
            return Arrays.equals(streamFrame.getStreamData(), expectedBytes)
                    && streamFrame.getOffset() == expectedOffset
                    && streamFrame.isFinal() == expectedFinalFlag;
        }
    }
}