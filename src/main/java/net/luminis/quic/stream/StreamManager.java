/*
 * Copyright © 2020, 2021 Peter Doornbosch
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

import net.luminis.quic.*;
import net.luminis.quic.frame.*;
import net.luminis.quic.log.Logger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import static net.luminis.quic.QuicConstants.TransportErrorCode.STREAM_LIMIT_ERROR;


public class StreamManager {

    private final Map<Integer, QuicStreamImpl> streams;
    private final Version quicVersion;
    private final QuicConnectionImpl connection;
    private FlowControl flowController;
    private final Role role;
    private final Logger log;
    private int maxOpenStreamIdUni;
    private int maxOpenStreamIdBidi;
    private int nextStreamId;
    private Consumer<QuicStream> peerInitiatedStreamCallback;
    private Long maxStreamsAcceptedByPeerBidi;
    private Long maxStreamsAcceptedByPeerUni;
    private final Semaphore openBidirectionalStreams;
    private final Semaphore openUnidirectionalStreams;
    private boolean maxOpenStreamsUniUpdateQueued;
    private boolean maxOpenStreamsBidiUpdateQueued;


    public StreamManager(QuicConnectionImpl quicConnection, Role role, Logger log, int maxOpenStreamsUni, int maxOpenStreamsBidi) {
        this.connection = quicConnection;
        this.role = role;
        this.log = log;
        this.maxOpenStreamIdUni = computeMaxStreamId(maxOpenStreamsUni, role.other(), false);
        this.maxOpenStreamIdBidi = computeMaxStreamId(maxOpenStreamsBidi, role.other(), true);
        quicVersion = Version.getDefault();
        streams = new ConcurrentHashMap<>();
        openBidirectionalStreams = new Semaphore(0);
        openUnidirectionalStreams = new Semaphore(0);
    }

    private int computeMaxStreamId(int maxStreams, Role peerRole, boolean bidirectional) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-4.6
        // "Only streams with a stream ID less than (max_stream * 4 + initial_stream_id_for_type) can be opened; "
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-2.1
        //  | 0x0  | Client-Initiated, Bidirectional  |
        int maxStreamId = maxStreams * 4;
        //  | 0x1  | Server-Initiated, Bidirectional  |
        if (peerRole == Role.Server && bidirectional) {
            maxStreamId += 1;
        }
        //  | 0x2  | Client-Initiated, Unidirectional |
        if (peerRole == Role.Client && !bidirectional) {
            maxStreamId += 2;
        }
        //  | 0x3  | Server-Initiated, Unidirectional |
        if (peerRole == Role.Client && bidirectional) {
            maxStreamId += 3;
        }
        return maxStreamId;
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
        return createStream(bidirectional, timeout, timeoutUnit,
                (quicVersion, streamId, connection, flowController, logger) -> new QuicStreamImpl(quicVersion, streamId, connection, flowController, logger));
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
        QuicStreamImpl stream = streamFactory.apply(quicVersion, streamId, connection, flowController, log);
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
        try {
            return (EarlyDataStream) createStream(bidirectional, 0, TimeUnit.MILLISECONDS,
                    (quicVersion, streamId, connection, flowController, logger) -> new EarlyDataStream(quicVersion, streamId, (QuicClientConnectionImpl) connection, flowController, logger));
        } catch (TimeoutException e) {
            return null;
        }
    }

    private synchronized int generateStreamId(boolean bidirectional) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-2.1:
        // "0x0  | Client-Initiated, Bidirectional"
        // "0x1  | Server-Initiated, Bidirectional"
        int id = (nextStreamId << 2) + (role == Role.Client? 0x00: 0x01);
        if (!bidirectional) {
            // "0x2  | Client-Initiated, Unidirectional |"
            // "0x3  | Server-Initiated, Unidirectional |"
            id += 0x02;
        }
        nextStreamId++;
        return id;
    }

    // TODO: inject FlowController in constructor (requires change in FlowController itself)
    public void setFlowController(FlowControl flowController) {
        this.flowController = flowController;
    }

    public void process(StreamFrame frame) throws TransportError {
        int streamId = frame.getStreamId();
        QuicStreamImpl stream = streams.get(streamId);
        if (stream != null) {
            stream.add(frame);
            // This implementation maintains a fixed maximum number of open streams, so when the peer closes a stream
            // it is allowed to open another.
            if (frame.isFinal() && isPeerInitiated(streamId)) {
                increaseMaxOpenStreams(streamId);
            }
        }
        else {
            if (isPeerInitiated(streamId)) {
                synchronized (this) {
                    if (isUni(streamId) && streamId < maxOpenStreamIdUni || isBidi(streamId) && streamId < maxOpenStreamIdBidi) {
                        log.debug("Receiving data for peer-initiated stream " + streamId + " (#" + ((streamId / 4) + 1) + " of this type)");
                        stream = new QuicStreamImpl(quicVersion, streamId, connection, flowController, log);
                        streams.put(streamId, stream);
                        stream.add(frame);
                        if (peerInitiatedStreamCallback != null) {
                            peerInitiatedStreamCallback.accept(stream);
                        }
                        if (frame.isFinal()) {
                            increaseMaxOpenStreams(streamId);
                        }
                    }
                    else {
                        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.11
                        // "An endpoint MUST terminate a connection with a STREAM_LIMIT_ERROR error if a peer opens more
                        //  streams than was permitted."
                        throw new TransportError(STREAM_LIMIT_ERROR);
                    }
                }
            }
            else {
                log.error("Receiving frame for non-existent stream " + streamId);
            }
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

    public void process(ResetStreamFrame resetStreamFrame) {
        QuicStreamImpl stream = streams.get(resetStreamFrame.getStreamId());
        if (stream != null) {
            // "An endpoint SHOULD copy the error code from the STOP_SENDING frame to the RESET_STREAM frame it sends, ..."
            stream.terminateStream(resetStreamFrame.getErrorCode(), resetStreamFrame.getFinalSize());
        }
    }

    private void increaseMaxOpenStreams(int streamId) {
        synchronized (this) {
            if (isUni(streamId)) {
                maxOpenStreamIdUni += 4;
                if (! maxOpenStreamsUniUpdateQueued) {
                    connection.send(this::createMaxStreamsUpdateUni, 9, EncryptionLevel.App, this::retransmitMaxStreams);  // Flush not necessary, as this method is called while processing received message.
                    maxOpenStreamsUniUpdateQueued = true;
                }
            } else {
                maxOpenStreamIdBidi += 4;
                if (! maxOpenStreamsBidiUpdateQueued) {
                    connection.send(this::createMaxStreamsUpdateBidi, 9, EncryptionLevel.App, this::retransmitMaxStreams);  // Flush not necessary, as this method is called while processing received message.
                    maxOpenStreamsBidiUpdateQueued = true;
                }
            }
        }
    }

    private QuicFrame createMaxStreamsUpdateUni(int maxSize) {
        if (maxSize < 9) {
            throw new ImplementationError();
        }
        synchronized (this) {
            maxOpenStreamsUniUpdateQueued = false;
        }

        // largest streamId < maxStreamId; e.g. client initiated: max-id = 6, server initiated: max-id = 7 => max streams = 1,
        return new MaxStreamsFrame(maxOpenStreamIdUni / 4, false);
    }

    private QuicFrame createMaxStreamsUpdateBidi(int maxSize) {
        if (maxSize < 9) {
            throw new ImplementationError();
        }
        synchronized (this) {
            maxOpenStreamsBidiUpdateQueued = false;
        }

        // largest streamId < maxStreamId; e.g. client initiated: max-id = 4, server initiated: max-id = 5 => max streams = 1,
        return new MaxStreamsFrame(maxOpenStreamIdBidi / 4, true);
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

    public synchronized void process(MaxStreamsFrame frame) {
        if (frame.isAppliesToBidirectional()) {
            if (frame.getMaxStreams() > maxStreamsAcceptedByPeerBidi) {
                int increment = (int) (frame.getMaxStreams() - maxStreamsAcceptedByPeerBidi);
                log.debug("increased max bidirectional streams with " + increment + " to " + frame.getMaxStreams());
                maxStreamsAcceptedByPeerBidi = frame.getMaxStreams();
                openBidirectionalStreams.release(increment);
            }
        }
        else {
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

    public synchronized void setPeerInitiatedStreamCallback(Consumer<QuicStream> streamProcessor) {
        peerInitiatedStreamCallback = streamProcessor;
    }

    /**
     * Set initial max bidirectional streams that the peer will accept.
     * @param initialMaxStreamsBidi
     */
    public synchronized void setInitialMaxStreamsBidi(long initialMaxStreamsBidi) {
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
    public synchronized void setInitialMaxStreamsUni(long initialMaxStreamsUni) {
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

    public synchronized long getMaxBidirectionalStreams() {
        return maxStreamsAcceptedByPeerBidi;
    }

    public synchronized long getMaxUnirectionalStreams() {
        return maxStreamsAcceptedByPeerUni;
    }

    interface QuicStreamSupplier {
        QuicStreamImpl apply(Version quicVersion, int streamId, QuicConnectionImpl connection, FlowControl flowController, Logger log);
    }
}

