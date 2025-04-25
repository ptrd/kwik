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

import tech.kwik.core.ConnectionConfig;
import tech.kwik.core.QuicConstants;
import tech.kwik.core.QuicStream;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.frame.*;
import tech.kwik.core.impl.*;
import tech.kwik.core.log.Logger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

import static tech.kwik.core.QuicConstants.TransportErrorCode.STREAM_LIMIT_ERROR;

/**
 * Manages all QUIC streams of a given connection.
 * Note that Kwik cannot handle more than 2147483647 (<code>Integer.MAX_INT</code>) streams in one connection.
 */
public class StreamManager {

    private static final Consumer<QuicStream> NO_OP_CONSUMER = (stream) -> {};

    private final Map<Integer, QuicStreamImpl> streams;
    private final Version quicVersion;
    private final QuicConnectionImpl connection;
    private final ExecutorService callbackExecutor;
    private volatile FlowControl flowController;
    private final Role role;
    private final Logger log;
    private volatile ConnectionConfig config;
    private volatile int currentUnidirectionalStreamIdLimit;
    private volatile int currentBidirectionalStreamIdLimit;
    private volatile Consumer<QuicStream> peerInitiatedStreamCallback;
    private volatile Long maxStreamsAcceptedByPeerBidi;
    private volatile Long maxStreamsAcceptedByPeerUni;
    private final Semaphore openBidirectionalStreams;
    private final Semaphore openUnidirectionalStreams;
    private volatile boolean maxOpenStreamsUniUpdateQueued;
    private volatile boolean maxOpenStreamsBidiUpdateQueued;
    private volatile long flowControlMax;
    private long flowControlLastAdvertised;
    private long flowControlIncrement;
    private final ReentrantLock maxOpenStreamsUpdateLock;
    private final ReentrantLock updateFlowControlLock;
    private final AtomicInteger nextStreamIdBidirectional;
    private final AtomicInteger nextStreamIdUnidirectional;
    private volatile int nextPeerInitiatedUnidirectionalStreamId;
    private volatile int nextPeerInitiatedBidirectionalStreamId;
    private long cumulativeReceiveOffset;
    private long absoluteUnidirectionalStreamIdLimit;
    private long absoluteBidirectionalStreamIdLimit;


    /**
     * Creates a stream manager for a given connection.
     *
     * @param quicConnection
     * @param role
     * @param log
     * @param config
     * @param callbackExecutor
     */
    public StreamManager(QuicConnectionImpl quicConnection, Role role, Logger log, ConnectionConfig config, ExecutorService callbackExecutor) {
        this.connection = quicConnection;
        this.role = role;
        this.log = log;

        quicVersion = Version.getDefault();
        streams = new ConcurrentHashMap<>();
        openBidirectionalStreams = new Semaphore(0);
        openUnidirectionalStreams = new Semaphore(0);
        peerInitiatedStreamCallback = NO_OP_CONSUMER;
        maxOpenStreamsUpdateLock = new ReentrantLock();
        updateFlowControlLock = new ReentrantLock();
        nextStreamIdBidirectional = new AtomicInteger();
        nextStreamIdUnidirectional = new AtomicInteger();

        initStreamIds();

        this.callbackExecutor = callbackExecutor;
        initialize(config);
    }

    public void initialize(ConnectionConfig config) {
        this.config = config;
        this.currentUnidirectionalStreamIdLimit = computeMaxStreamIdLimit(config.maxOpenPeerInitiatedUnidirectionalStreams(), role.other(), false);
        this.currentBidirectionalStreamIdLimit = computeMaxStreamIdLimit(config.maxOpenPeerInitiatedBidirectionalStreams(), role.other(), true);
        absoluteUnidirectionalStreamIdLimit = computeMaxStreamIdLimit((int) Long.min(Integer.MAX_VALUE, config.maxTotalPeerInitiatedUnidirectionalStreams()), role.other(), false);
        absoluteBidirectionalStreamIdLimit = computeMaxStreamIdLimit((int) Long.min(Integer.MAX_VALUE, config.maxTotalPeerInitiatedBidirectionalStreams()), role.other(), true);

        initConnectionFlowControl(config.maxConnectionBufferSize());

    }

    /**
     * Computes the limit for a stream id, based on the given maximum number of stream, peer role and stream type.
     * Only streams with an id less than this limit can be opened.
     * @param maxStreams
     * @param peerRole
     * @param bidirectional
     * @return
     */
    private int computeMaxStreamIdLimit(int maxStreams, Role peerRole, boolean bidirectional) {
        if (maxStreams < 0) {
            return 0;
        }

        // https://www.rfc-editor.org/rfc/rfc9000.html#name-controlling-concurrency
        // "Only streams with a stream ID less than (max_stream * 4 + initial_stream_id_for_type) can be opened; "
        int initialStreamIdForType = Integer.MIN_VALUE;
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-stream-types-and-identifier
        //  | 0x0  | Client-Initiated, Bidirectional  |
        if (peerRole == Role.Client && bidirectional) {
            initialStreamIdForType = 0;
        }
        //  | 0x1  | Server-Initiated, Bidirectional  |
        if (peerRole == Role.Server && bidirectional) {
            initialStreamIdForType = 1;
        }
        //  | 0x2  | Client-Initiated, Unidirectional |
        if (peerRole == Role.Client && !bidirectional) {
            initialStreamIdForType = 2;
        }
        //  | 0x3  | Server-Initiated, Unidirectional |
        if (peerRole == Role.Server && !bidirectional) {
            initialStreamIdForType = 3;
        }
        int maxStreamId = maxStreams * 4 + initialStreamIdForType;
        return (maxStreamId > 0)? maxStreamId: Integer.MAX_VALUE;  // < 0 means integer overflow, to "limit" to max int.
    }

    private void initStreamIds() {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-stream-types-and-identifier
        // "0x00	Client-Initiated, Bidirectional
        //  0x01	Server-Initiated, Bidirectional
        //  0x02	Client-Initiated, Unidirectional
        //  0x03	Server-Initiated, Unidirectional"
        nextStreamIdBidirectional.set(role == Role.Client? 0x00 : 0x01);
        nextStreamIdUnidirectional.set(role == Role.Client? 0x02 : 0x03);

        nextPeerInitiatedUnidirectionalStreamId = role == Role.Client? 0x03 : 0x02;
        nextPeerInitiatedBidirectionalStreamId = role == Role.Client? 0x01 : 0x00;
    }

    protected void initConnectionFlowControl(long initialMaxData) {
        flowControlMax = initialMaxData;
        flowControlLastAdvertised = flowControlMax;
        flowControlIncrement = flowControlMax / 10;
    }

    public QuicStream createStream(boolean bidirectional) {
        try {
            return createStream(bidirectional, 10_000, TimeUnit.DAYS);
        } catch (TimeoutException e) {
            // Impossible; just to satisfy compiler
            throw new RuntimeException();
        }
    }

    public QuicStream createStream(boolean bidirectional, long timeout, TimeUnit timeoutUnit) throws TimeoutException {
        QuicStreamSupplier streamCreator = (streamId) -> new QuicStreamImpl(quicVersion, streamId, role, connection, this, flowController, log);
        return createStream(bidirectional, timeout, timeoutUnit, streamCreator);
    }

    private QuicStreamImpl createStream(boolean bidirectional, long timeout, TimeUnit unit, QuicStreamSupplier streamFactory) throws TimeoutException {
        try {
            boolean acquired;
            if (bidirectional) {
                acquired = openBidirectionalStreams.tryAcquire(timeout, unit);
            }
            else {
                acquired = openUnidirectionalStreams.tryAcquire(timeout, unit);
            }
            if (!acquired) {
                throw new TimeoutException();
            }
        } catch (InterruptedException e) {
            log.debug("blocked createStream operation is interrupted");
            throw new TimeoutException("operation interrupted");
        }

        int streamId = generateStreamId(bidirectional);
        QuicStreamImpl stream = streamFactory.apply(streamId);
        streams.put(streamId, stream);
        return stream;
    }

    /**
     * Creates a quic stream that is able to send early data.
     * Note that this method will not block; if the stream cannot be created due to no stream credit, null is returned.
     * @param bidirectional
     * @return
     */
    public EarlyDataStream createEarlyDataStream(boolean bidirectional) {
        assert role == Role.Client;
        try {
            QuicStreamSupplier streamCreator = (streamId) -> new EarlyDataStream(quicVersion, streamId, (QuicClientConnectionImpl) connection, this, flowController, log);
            return (EarlyDataStream) createStream(bidirectional, 0, TimeUnit.MILLISECONDS, streamCreator);
        }
        catch (TimeoutException e) {
            return null;
        }
    }

    private int generateStreamId(boolean bidirectional) {
        if (bidirectional) {
            return nextStreamIdBidirectional.getAndAdd(4);
        }
        else {
            return nextStreamIdUnidirectional.getAndAdd(4);
        }
    }

    public void setFlowController(FlowControl flowController) {
        this.flowController = flowController;
    }

    public void process(StreamFrame frame) throws TransportError {
        int streamId = frame.getStreamId();
        QuicStreamImpl stream = streams.get(streamId);
        checkConnectionFlowControl(stream, frame);
        if (stream != null) {
            cumulativeReceiveOffset += stream.addStreamData(frame);
        }
        else {
            if (isPeerInitiated(streamId)) {
                QuicStreamImpl peerInitiatedStream = createPeerInitiatedStream(streamId);
                if (peerInitiatedStream != null) {
                    cumulativeReceiveOffset += peerInitiatedStream.addStreamData(frame);
                }
            }
            else {
                log.warn("Receiving frame for non-existent stream " + streamId);
            }
        }
    }

    private QuicStreamImpl createPeerInitiatedStream(int requestedStreamId) throws TransportError {
        if (isUni(requestedStreamId) && requestedStreamId < currentUnidirectionalStreamIdLimit || isBidi(requestedStreamId) && requestedStreamId < currentBidirectionalStreamIdLimit) {
            if (isUni(requestedStreamId)) {
                createPeerInitiatedStreams(requestedStreamId, nextPeerInitiatedUnidirectionalStreamId, () -> nextPeerInitiatedUnidirectionalStreamId = requestedStreamId + 4);
            }
            else {
                assert isBidi(requestedStreamId);
                createPeerInitiatedStreams(requestedStreamId, nextPeerInitiatedBidirectionalStreamId, () -> nextPeerInitiatedBidirectionalStreamId = requestedStreamId + 4);
            }
        }
        else {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6
            // "An endpoint that receives a frame with a stream ID exceeding the limit it has sent MUST treat this as a
            //  connection error of type STREAM_LIMIT_ERROR"
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11
            // "An endpoint MUST terminate a connection with a STREAM_LIMIT_ERROR error if a peer opens more streams
            //  than was permitted."
            throw new TransportError(STREAM_LIMIT_ERROR);
        }
        return streams.get(requestedStreamId);
    }

    private void createPeerInitiatedStreams(int requestedStreamId, int nextStreamId, Runnable nextStreamIdUpdate) throws TransportError {
        if (requestedStreamId >= nextStreamId) {
            assert (requestedStreamId - nextStreamId) % 4 == 0;
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-receiving-stream-states
            // "Before a stream is created, all streams of the same type with lower-numbered stream IDs MUST be created."
            for (int streamId = nextStreamId; streamId <= requestedStreamId; streamId += 4) {
                QuicStreamImpl stream = new QuicStreamImpl(quicVersion, streamId, role, connection, this, flowController, log);
                streams.put(streamId, stream);
                callbackExecutor.submit(() -> peerInitiatedStreamCallback.accept(stream));
            }
            nextStreamIdUpdate.run();
        }
        else {
            // Attempt to re-open a closed stream, could be due to re-ordering, so ignore
            log.warn("Receiving data for already closed peer-initiated stream " + requestedStreamId + " (ignoring)");
        }
    }

    public void process(StopSendingFrame stopSendingFrame) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-solicited-state-transitions
        // "A STOP_SENDING frame requests that the receiving endpoint send a RESET_STREAM frame."
        QuicStreamImpl stream = streams.get(stopSendingFrame.getStreamId());
        if (stream != null) {
            // "An endpoint SHOULD copy the error code from the STOP_SENDING frame to the RESET_STREAM frame it sends, ..."
            stream.resetStream(stopSendingFrame.getErrorCode());
        }
    }

    public void process(ResetStreamFrame resetStreamFrame) throws TransportError {
        QuicStreamImpl stream = streams.get(resetStreamFrame.getStreamId());
        if (stream != null) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
            // "A receiver of RESET_STREAM can discard any data that it already received on that stream."
            cumulativeReceiveOffset += stream.terminateStream(resetStreamFrame.getErrorCode(), resetStreamFrame.getFinalSize());
        }
    }

    public void updateConnectionFlowControl(int size) {
        try {
            updateFlowControlLock.lock();

            flowControlMax += size;
            if (flowControlMax - flowControlLastAdvertised > flowControlIncrement) {
                connection.send(new MaxDataFrame(flowControlMax), f -> {}, true);
                flowControlLastAdvertised = flowControlMax;
            }
        }
        finally {
            updateFlowControlLock.unlock();
        }
    }

    private void checkConnectionFlowControl(QuicStreamImpl receivingStream, StreamFrame frame) throws TransportError {
        if (receivingStream != null || isNewPeerInitiated(frame.getStreamId())) {
            long receivingStreamMaxOffset = receivingStream != null ? receivingStream.getReceivedMaxOffset() : 0;
            if (frame.getUpToOffset() > receivingStreamMaxOffset) {
                long increment = frame.getUpToOffset() - receivingStreamMaxOffset;
                if (cumulativeReceiveOffset + increment > flowControlMax) {
                    log.error("Flow control error on stream: " + frame.getStreamId() + ":" + cumulativeReceiveOffset + " + " + increment + " > " + flowControlMax);
                    throw new TransportError(QuicConstants.TransportErrorCode.FLOW_CONTROL_ERROR);
                }
            }
        }
        // else: (receivingStream is null because) stream already closed, so ignore!
    }

    private boolean isNewPeerInitiated(int streamId) {
        return isPeerInitiated(streamId) &&
                (isUni(streamId) && streamId >= nextPeerInitiatedUnidirectionalStreamId
                        || isBidi(streamId) && streamId >= nextPeerInitiatedBidirectionalStreamId);
    }

    void streamClosed(int streamId) {
        // This implementation maintains a fixed maximum number of open streams, so when a stream initiated by the peer
        // is closed, it is allowed to open another.
        streams.remove(streamId);
        if (isPeerInitiated(streamId)) {
            increaseMaxOpenStreams(streamId);
        }
    }

    private void increaseMaxOpenStreams(int streamId) {
        // Can be called concurrently, so lock
        try {
            maxOpenStreamsUpdateLock.lock();
            if (isUni(streamId) && currentUnidirectionalStreamIdLimit + 4 < absoluteUnidirectionalStreamIdLimit) {
                currentUnidirectionalStreamIdLimit += 4;
                if (! maxOpenStreamsUniUpdateQueued) {
                    connection.send(this::createMaxStreamsUpdateUni, 9, EncryptionLevel.App, this::retransmitMaxStreams);  // Flush not necessary, as this method is called while processing received message.
                    maxOpenStreamsUniUpdateQueued = true;
                }
            }
            else if (isBidi(streamId) && currentBidirectionalStreamIdLimit + 4 < absoluteBidirectionalStreamIdLimit) {
                currentBidirectionalStreamIdLimit += 4;
                if (! maxOpenStreamsBidiUpdateQueued) {
                    connection.send(this::createMaxStreamsUpdateBidi, 9, EncryptionLevel.App, this::retransmitMaxStreams);  // Flush not necessary, as this method is called while processing received message.
                    maxOpenStreamsBidiUpdateQueued = true;
                }
            }
        }
        finally {
            maxOpenStreamsUpdateLock.unlock();
        }
    }

    private QuicFrame createMaxStreamsUpdateUni(int maxFrameSize) {
        if (maxFrameSize < 9) {
            throw new ImplementationError();
        }
        try {
            maxOpenStreamsUpdateLock.lock();
            maxOpenStreamsUniUpdateQueued = false;
        }
        finally {
            maxOpenStreamsUpdateLock.unlock();
        }

        // largest streamId < maxStreamId; e.g. client initiated: max-id = 6, server initiated: max-id = 7 => max streams = 1,
        return new MaxStreamsFrame(currentUnidirectionalStreamIdLimit / 4, false);
    }

    private QuicFrame createMaxStreamsUpdateBidi(int maxFrameSize) {
        if (maxFrameSize < 9) {
            throw new ImplementationError();
        }
        try {
            maxOpenStreamsUpdateLock.lock();
            maxOpenStreamsBidiUpdateQueued = false;
        }
        finally {
            maxOpenStreamsUpdateLock.unlock();
        }

        // largest streamId < maxStreamId; e.g. client initiated: max-id = 4, server initiated: max-id = 5 => max streams = 1,
        return new MaxStreamsFrame(currentBidirectionalStreamIdLimit / 4, true);
    }

    void retransmitMaxStreams(QuicFrame frame) {
        MaxStreamsFrame lostFrame = ((MaxStreamsFrame) frame);
        if (lostFrame.isAppliesToBidirectional()) {
            connection.send(createMaxStreamsUpdateBidi(Integer.MAX_VALUE), this::retransmitMaxStreams);
        }
        else {
            connection.send(createMaxStreamsUpdateUni(Integer.MAX_VALUE), this::retransmitMaxStreams);
        }
    }

    private boolean isPeerInitiated(int streamId) {
        return streamId % 2 == (role == Role.Client? 1 : 0);
    }

    private boolean isUni(int streamId) {
        return streamId % 4 > 1;
    }

    private boolean isBidi(int streamId) {
        return streamId % 4 < 2;
    }

    public void process(MaxStreamsFrame frame) {
        if (frame.isAppliesToBidirectional()) {
            assert maxStreamsAcceptedByPeerBidi != null;  // Should already been set during connection setup (from transport parameters).
            if (frame.getMaxStreams() > maxStreamsAcceptedByPeerBidi) {
                int increment = (int) (frame.getMaxStreams() - maxStreamsAcceptedByPeerBidi);
                log.debug("increased max bidirectional streams with " + increment + " to " + frame.getMaxStreams());
                maxStreamsAcceptedByPeerBidi = frame.getMaxStreams();
                openBidirectionalStreams.release(increment);
            }
        }
        else {
            assert maxStreamsAcceptedByPeerUni != null;  // Should already been set during connection setup (from transport parameters).
            if (frame.getMaxStreams() > maxStreamsAcceptedByPeerUni) {
                int increment = (int) (frame.getMaxStreams() - maxStreamsAcceptedByPeerUni);
                log.debug("increased max unidirectional streams with " + increment + " to " + frame.getMaxStreams());
                maxStreamsAcceptedByPeerUni = frame.getMaxStreams();
                openUnidirectionalStreams.release(increment);
            }
        }
    }

    public void abortAll() {
        streams.values().stream().forEach(s -> s.abort());
    }

    public void setPeerInitiatedStreamCallback(Consumer<QuicStream> streamProcessor) {
        if (streamProcessor != null) {
            peerInitiatedStreamCallback = streamProcessor;
        }
        else {
            peerInitiatedStreamCallback = NO_OP_CONSUMER;
        }
    }

    /**
     * Set initial max bidirectional streams that the peer will accept.
     * @param initialMaxStreamsBidi
     */
    public void setInitialMaxStreamsBidi(long initialMaxStreamsBidi) {
        if (maxStreamsAcceptedByPeerBidi == null || initialMaxStreamsBidi >= maxStreamsAcceptedByPeerBidi) {
            log.debug("Initial max bidirectional stream: " + initialMaxStreamsBidi);
            maxStreamsAcceptedByPeerBidi = initialMaxStreamsBidi;
            if (initialMaxStreamsBidi > Integer.MAX_VALUE) {
                log.error("Server initial max streams bidirectional is larger than supported; limiting to " + Integer.MAX_VALUE);
                initialMaxStreamsBidi = Integer.MAX_VALUE;
            }
            openBidirectionalStreams.release((int) initialMaxStreamsBidi);
        }
        else {
            log.error("Attempt to reduce value of initial_max_streams_bidi from " + maxStreamsAcceptedByPeerBidi + " to " + initialMaxStreamsBidi + "; ignoring.");
        }
    }

    /**
     * Set initial max unidirectional streams that the peer will accept.
     * @param initialMaxStreamsUni
     */
    public void setInitialMaxStreamsUni(long initialMaxStreamsUni) {
        if (maxStreamsAcceptedByPeerUni == null || initialMaxStreamsUni >= maxStreamsAcceptedByPeerUni) {
            log.debug("Initial max unidirectional stream: " + initialMaxStreamsUni);
            maxStreamsAcceptedByPeerUni = initialMaxStreamsUni;
            if (initialMaxStreamsUni > Integer.MAX_VALUE) {
                log.error("Server initial max streams unidirectional is larger than supported; limiting to " + Integer.MAX_VALUE);
                initialMaxStreamsUni = Integer.MAX_VALUE;
            }
            openUnidirectionalStreams.release((int) initialMaxStreamsUni);
        }
        else {
            log.error("Attempt to reduce value of initial_max_streams_uni from " + maxStreamsAcceptedByPeerUni + " to " + initialMaxStreamsUni + "; ignoring.");
        }
    }

    int openStreamCount() {
        return streams.size();
    }

    public long getMaxBidirectionalStreams() {
        return maxStreamsAcceptedByPeerBidi;
    }

    public long getMaxUnidirectionalStreams() {
        return maxStreamsAcceptedByPeerUni;
    }

    public long getMaxUnidirectionalStreamBufferSize() {
        return config.maxUnidirectionalStreamBufferSize();
    }

    public long getMaxBidirectionalStreamBufferSize() {
        return config.maxBidirectionalStreamBufferSize();
    }

    public void setDefaultUnidirectionalStreamReceiveBufferSize(long newSize) {
        config = ConnectionConfigImpl.cloneWithMaxUnidirectionalStreamReceiveBufferSize(config, newSize);
    }

    public void setDefaultBidirectionalStreamReceiveBufferSize(long newSize) {
        config = ConnectionConfigImpl.cloneWithMaxBidirectionalStreamReceiveBufferSize(config, newSize);
    }

    interface QuicStreamSupplier {
        QuicStreamImpl apply(int streamId);
    }
}
