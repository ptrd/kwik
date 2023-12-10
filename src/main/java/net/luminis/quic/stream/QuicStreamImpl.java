/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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
package net.luminis.quic.stream;

import net.luminis.quic.QuicStream;
import net.luminis.quic.core.QuicConnectionImpl;
import net.luminis.quic.core.Role;
import net.luminis.quic.core.TransportError;
import net.luminis.quic.core.Version;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.NullLogger;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.locks.ReentrantLock;


public class QuicStreamImpl implements QuicStream {

    protected final Version quicVersion;
    protected final int streamId;
    protected final Role role;
    protected final QuicConnectionImpl connection;
    private final StreamManager streamManager;
    protected final Logger log;
    private final StreamInputStream inputStream;
    private final StreamOutputStream outputStream;
    private volatile boolean outputClosed;
    private volatile boolean inputClosed;
    private final ReentrantLock stateLock;


    public QuicStreamImpl(int streamId, Role role, QuicConnectionImpl connection, StreamManager streamManager, FlowControl flowController) {
        this(Version.getDefault(), streamId, role, connection, streamManager, flowController, new NullLogger());
    }

    public QuicStreamImpl(int streamId, Role role, QuicConnectionImpl connection, StreamManager streamManager, FlowControl flowController, Logger log) {
        this(Version.getDefault(), streamId, role, connection, streamManager, flowController, log);
    }

    public QuicStreamImpl(Version quicVersion, int streamId, Role role, QuicConnectionImpl connection, StreamManager streamManager, FlowControl flowController, Logger log) {
        this(quicVersion, streamId, role, connection, streamManager, flowController, log, null);
    }

    QuicStreamImpl(Version quicVersion, int streamId, Role role, QuicConnectionImpl connection, StreamManager streamManager, FlowControl flowController, Logger log, Integer sendBufferSize) {
        this.quicVersion = quicVersion;
        this.streamId = streamId;
        this.role = role;
        this.connection = connection;
        this.streamManager = streamManager;
        this.log = log;

        inputStream = new StreamInputStream(this);
        outputStream = createStreamOutputStream(sendBufferSize, flowController);

        stateLock = new ReentrantLock();
    }

    @Override
    public InputStream getInputStream() {
        return inputStream;
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    /**
     * Adds a newly received frame to the stream.
     *
     * This method is intentionally package-protected, as it should only be called by the (Stream)Packet processor.
     * @param frame
     */
    void add(StreamFrame frame) throws TransportError {
        inputStream.add(frame);
    }

    /**
     * This method is intentionally package-protected, as it should only be called by the (Stream)Packet processor.
     * @return  largest offset received so far
     */
    long getCurrentReceiveOffset() {
        return inputStream.getCurrentReceiveOffset();
    }

    @Override
    public int getStreamId() {
        return streamId;
    }

    @Override
    public boolean isUnidirectional() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-2.1
        // "The second least significant bit (0x2) of the stream ID distinguishes
        //   between bidirectional streams (with the bit set to 0) and
        //   unidirectional streams (with the bit set to 1)."
        return (streamId & 0x0002) == 0x0002;
    }

    @Override
    public boolean isClientInitiatedBidirectional() {
        // "Client-initiated streams have even-numbered stream IDs (with the bit set to 0)"
        return (streamId & 0x0003) == 0x0000;
    }

    @Override
    public boolean isServerInitiatedBidirectional() {
        // "server-initiated streams have odd-numbered stream IDs"
        return (streamId & 0x0003) == 0x0001;
    }

    public boolean isSelfInitiated() {
        return role == Role.Client && (streamId & 0x0001) == 0x0000
                || role == Role.Server && (streamId & 0x0001) == 0x0001;
    }

    public boolean isPeerInitiated() {
        return !isSelfInitiated();
    }

    @Override
    public void abortReading(long applicationProtocolErrorCode) {
        inputStream.abortReading(applicationProtocolErrorCode);
    }

    @Override
    public void resetStream(long errorCode) {
        outputStream.reset(errorCode);
    }

    @Override
    public String toString() {
        return "Stream " + streamId;
    }

    protected StreamOutputStream createStreamOutputStream(Integer sendBufferSize, FlowControl flowControl) {
        return new StreamOutputStream(this, sendBufferSize, flowControl);
    }

    /**
     * Terminates the receiving input stream (abruptly). Is called when peer sends a RESET_STREAM frame
     *
     * This method is intentionally package-protected, as it should only be called by the StreamManager class.
     *
     * @param errorCode
     * @param finalSize
     */
    void terminateStream(long errorCode, long finalSize) throws TransportError {
        inputStream.terminate(errorCode, finalSize);
    }

    // TODO: QuicStream should have a close method that closes both input and output stream and releases all resources and marks itself as terminated.

    /**
     * Resets the output stream so data can again be send from the start of the stream (offset 0). Note that in such
     * cases the caller must (again) provide the data to be sent.
     */
    protected void resetOutputStream() {
        outputStream.resetOutputStream();
    }

    protected void stopFlowControl() {
        outputStream.stopFlowControl();
    }

    void abort() {
        outputStream.abort();
        inputStream.abort();
    }

    void updateConnectionFlowControl(int bytesRead) {
        streamManager.updateConnectionFlowControl(bytesRead);
    }

    void outputClosed() {
        try {
            stateLock.lock();
            outputClosed = true;
            if (isBidirectional() && inputClosed || isUnidirectional()) {
                streamManager.streamClosed(streamId);
            }
        }
        finally {
            stateLock.unlock();
        }
    }

    void inputClosed() {
        try {
            stateLock.lock();
            inputClosed = true;
            if (isBidirectional() && outputClosed || isUnidirectional()) {
                streamManager.streamClosed(streamId);
            }
        }
        finally {
            stateLock.unlock();
        }
    }
}
