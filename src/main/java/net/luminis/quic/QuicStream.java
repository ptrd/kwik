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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;


public class QuicStream {

    protected static long waitForNextFrameTimeout = Long.MAX_VALUE;

    private Object addMonitor = new Object();
    private final Version quicVersion;
    private final int streamId;
    private final QuicConnection connection;
    private final Logger log;
    private final BlockingQueue<StreamFrame> queuedFrames;
    private StreamFrame currentFrame;
    private int currentOffset;
    private int lastContiguousOffsetReceived;
    private Map<Integer, StreamFrame> receivedFrames;
    private StreamInputStream inputStream;
    private StreamOutputStream outputStream;
    private volatile boolean aborted;
    private volatile Thread blocking;


    public QuicStream(int streamId, QuicConnection connection, Logger log) {
        this(Version.IETF_draft_17, streamId, connection, log);
    }

    public QuicStream(Version quicVersion, int streamId, QuicConnection connection, Logger log) {
        this.quicVersion = quicVersion;
        this.streamId = streamId;
        this.connection = connection;
        this.log = log;
        queuedFrames = new LinkedBlockingQueue<>();  // Queued frames are the ones eligible for reading, because they are contiguous
        receivedFrames = new ConcurrentHashMap<>();  // Received frames are the ones not (yet) eligible for reading, because they are non-continguous
        inputStream = new StreamInputStream();
        outputStream = new StreamOutputStream();
    }

    public InputStream getInputStream() {
        return inputStream;
    }

    public OutputStream getOutputStream() {
        return outputStream;
    }

    /**
     * Adds a newly received frame to the stream.
     *
     * This method is intentionally package-protected, as it should only be called by the (Stream)Packet processor.
     * @param frame
     */
    void add(StreamFrame frame) {
        String logMessage = null;

        synchronized (addMonitor) {
            if (frame.getOffset() == lastContiguousOffsetReceived) {
                lastContiguousOffsetReceived += frame.getLength();
                queuedFrames.add(frame);
                if (receivedFrames.containsKey(lastContiguousOffsetReceived)) {
                    // Next frame was already received; move it to the incoming queue
                    StreamFrame nextFrame = receivedFrames.remove(lastContiguousOffsetReceived);
                    queuedFrames.add(nextFrame);
                }
            }
            else {
                // Store frame for later use
                if (! receivedFrames.containsKey(frame.getOffset())) {
                    receivedFrames.put(frame.getOffset(), frame);
                }
                else {
                    logMessage = "Received duplicate frame " + frame;
                }
            }
        }
        if (logMessage != null) {
            log.debug(logMessage);
        }
    }

    public int getStreamId() {
        return streamId;
    }


    private class StreamInputStream extends InputStream {
        @Override
        public int read() throws IOException {
            if (aborted)
                throw new ProtocolException("Connection aborted");

            blocking = Thread.currentThread();  // TODO: this works for one blocking reader thread only
            if (currentFrame == null) {
                try {
                    // Because the read method is supposed to block, the timeout should be (nearly) infinite.
                    currentFrame = queuedFrames.poll(waitForNextFrameTimeout, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    if (aborted) {
                        blocking = null;
                        throw new ProtocolException("Connection aborted");
                    }
                    /* Nothing to do, currentFrame will stay null. */ }
                if (currentFrame == null) {
                    blocking = null;
                    throw new SocketTimeoutException();
                }
            }
            blocking = null;
            if (currentOffset < currentFrame.getOffset() + currentFrame.getLength()) {
                byte data = currentFrame.getStreamData()[currentOffset - currentFrame.getOffset()];
                currentOffset++;
                return data;
            }
            else {
                if (currentFrame.isFinal()) {
                    return -1;
                }
                else {
                    currentFrame = null;
                    return read();
                }
            }
        }
    }

    private class StreamOutputStream extends OutputStream {
        int currentOffset;

        @Override
        public void write(byte[] data) throws IOException {
            write(data, 0, data.length);
        }

        @Override
        public void write(byte[] data, int off, int len) throws IOException {
            int maxDataPerFrame = connection.getMaxPacketSize() - StreamFrame.maxOverhead() - connection.getMaxShortHeaderPacketOverhead();
            int remaining = len;
            int offsetInDataArray = off;
            while (remaining > 0) {
                int bytesInFrame = Math.min(maxDataPerFrame, remaining);
                connection.send(new StreamFrame(quicVersion, streamId, currentOffset, data, offsetInDataArray, bytesInFrame, false));
                remaining -= bytesInFrame;
                offsetInDataArray += bytesInFrame;
                currentOffset += bytesInFrame;
            }
        }

        @Override
        public void write(int dataByte) throws IOException {
            connection.send(new StreamFrame(quicVersion, streamId, currentOffset, new byte[] {(byte) dataByte}, false));
            currentOffset += 1;
        }

        @Override
        public void flush() throws IOException {
            // No-op, this implementation flushes immediately.
        }

        @Override
        public void close() throws IOException {
            connection.send(new StreamFrame(quicVersion, streamId, currentOffset, new byte[0], true));
        }
    }

    void abort() {
        aborted = true;
        if (blocking != null) {
            blocking.interrupt();
        }
    }

}
