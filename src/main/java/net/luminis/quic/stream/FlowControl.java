/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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
import net.luminis.quic.frame.MaxDataFrame;
import net.luminis.quic.frame.MaxStreamDataFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.log.NullLogger;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static net.luminis.quic.QuicConstants.TransportErrorCode.STREAM_STATE_ERROR;

/**
 * Keeps track of connection and stream flow control limits imposed by the peer.
 */
public class FlowControl {

    private final Role role;

    // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-18.2

    // "The initial maximum data parameter is an integer value that contains the initial value for the maximum
    //  amount of data that can be sent on the connection."
    private final long initialMaxData;

    // "initial_max_stream_data_bidi_local (0x0005):  This parameter is an integer value specifying the initial flow control limit for
    //  locally-initiated bidirectional streams.
    private final long initialMaxStreamDataBidiLocal;

    // "initial_max_stream_data_bidi_remote (0x0006):  This parameter is an integer value specifying the initial flow control limit for peer-
    //  initiated bidirectional streams. "
    private final long initialMaxStreamDataBidiRemote;

    // "initial_max_stream_data_uni (0x0007):  This parameter is an integer value specifying the initial flow control limit for unidirectional
    //  streams."
    private final long initialMaxStreamDataUni;

    // The maximum amount of data that can be sent (to the peer) on the connection as a whole
    private long maxDataAllowed;
    // The maximum amount of data that can be sent on the connection, that is already assigned to a particular stream
    private long maxDataAssigned;
    // The maximum amount of data that a stream would be allowed to send (to the peer), ignoring possible connection limit
    private Map<Integer, Long> maxStreamDataAllowed;
    // The maximum amount of data that is already assigned to a stream (i.e. already sent, or upon being sent)
    private Map<Integer, Long> maxStreamDataAssigned;
    private final Logger log;
    private final Map<Integer, FlowControlUpdateListener> streamListeners;
    private int maxOpenedStreamId;


    public FlowControl(Role role, long initialMaxData, long initialMaxStreamDataBidiLocal, long initialMaxStreamDataBidiRemote, long initialMaxStreamDataUni) {
        this(role, initialMaxData, initialMaxStreamDataBidiLocal, initialMaxStreamDataBidiRemote, initialMaxStreamDataUni, new NullLogger());
    }

    public FlowControl(Role role, long initialMaxData, long initialMaxStreamDataBidiLocal, long initialMaxStreamDataBidiRemote, long initialMaxStreamDataUni, Logger log) {
        this.role = role;
        this.initialMaxData = initialMaxData;
        this.initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal;
        this.initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote;
        this.initialMaxStreamDataUni = initialMaxStreamDataUni;
        this.log = log;
        this.streamListeners = new ConcurrentHashMap<>();

        maxDataAllowed = initialMaxData;
        maxDataAssigned = 0;
        maxStreamDataAllowed = new HashMap<>();
        maxStreamDataAssigned = new HashMap<>();
    }

    /**
     * Request to increase the flow control limit for the indicated stream to the indicated value. Whether this is
     * possible depends on whether the stream flow control limit allows this and whether the connection flow control
     * limit has enough "unused" credits.
     * @param stream
     * @param requestedLimit
     * @return the new flow control limit for the stream: the offset of the last byte sent on the stream may not past this limit.
     */
    public long increaseFlowControlLimit(QuicStream stream, long requestedLimit) {
        int streamId = stream.getStreamId();
        synchronized (this) {
            long possibleStreamIncrement = currentStreamCredits(stream);
            long requestedIncrement = requestedLimit - maxStreamDataAssigned.get(streamId);
            long proposedStreamIncrement = Long.min(requestedIncrement, possibleStreamIncrement);

            if (requestedIncrement < 0) {
                throw new IllegalArgumentException();
            }

            maxDataAssigned += proposedStreamIncrement;
            long newStreamLimit = maxStreamDataAssigned.get(streamId) + proposedStreamIncrement;
            maxStreamDataAssigned.put(streamId, newStreamLimit);

            return newStreamLimit;
        }
    }

    /**
     * Returns the maximum flow control limit for the given stream, if it was requested now. Note that this limit
     * cannot be used to send data on the stream, as the flow control credits are not yet reserved.
     * @param stream
     * @return
     */
    public long getFlowControlLimit(QuicStream stream) {
        synchronized (this) {
            return maxStreamDataAssigned.get(stream.getStreamId()) + currentStreamCredits(stream);
        }
    }

    /**
     * Returns the reason why a given stream is blocked, which can be due that the stream flow control limit is reached
     * or the connection data limit is reached.
     * @param stream
     * @return
     */
    public BlockReason getFlowControlBlockReason(QuicStream stream) {
        int streamId = stream.getStreamId();
        if (maxStreamDataAssigned.get(streamId).equals(maxStreamDataAllowed.get(streamId))) {
            return BlockReason.STREAM_DATA_BLOCKED;
        }
        if (maxDataAllowed == maxDataAssigned) {
            return BlockReason.DATA_BLOCKED;
        }

        return BlockReason.NOT_BLOCKED;
    }

    /**
     * Returns the current connection flow control limit.
     * @return  current connection flow control limit
     */
    public long getConnectionDataLimit() {
        return maxDataAllowed;
    }

    /**
     * Update initial values. This can happen in a client that has sent 0-RTT data, for which it has used remembered
     * values and that updates the values when the ServerHello message is received.
     * Hence: only called by a client.
     * @param peerTransportParameters
     */
    public synchronized void updateInitialValues(TransportParameters peerTransportParameters) {
        if (role == Role.Server) {
            throw new ImplementationError();
        }

        if (peerTransportParameters.getInitialMaxData() > initialMaxData) {
            log.info("Increasing initial max data from " + initialMaxData + " to " + peerTransportParameters.getInitialMaxData());
            if (peerTransportParameters.getInitialMaxData() > maxDataAllowed) {
                maxDataAllowed = peerTransportParameters.getInitialMaxData();
            }
        }
        else if (peerTransportParameters.getInitialMaxData() < initialMaxData) {
            log.error("Ignoring attempt to reduce initial max data from " + initialMaxData + " to " + peerTransportParameters.getInitialMaxData());
        }

        if (peerTransportParameters.getInitialMaxStreamDataBidiLocal() > initialMaxStreamDataBidiLocal) {
            log.info("Increasing initial max data from " + initialMaxStreamDataBidiLocal + " to " + peerTransportParameters.getInitialMaxStreamDataBidiLocal());
            maxStreamDataAllowed.entrySet().stream()
                    // Find all server initiated bidirectional streams
                    .filter(entry -> entry.getKey() % 4 == 1)
                    .forEach(entry -> {
                        if (peerTransportParameters.getInitialMaxStreamDataBidiLocal() > entry.getValue()) {
                            maxStreamDataAllowed.put(entry.getKey(), peerTransportParameters.getInitialMaxStreamDataBidiLocal());
                        }
                    });
        }
        else if (peerTransportParameters.getInitialMaxStreamDataBidiLocal() < initialMaxStreamDataBidiLocal) {
            log.error("Ignoring attempt to reduce max data from " + initialMaxStreamDataBidiLocal + " to " + peerTransportParameters.getInitialMaxStreamDataBidiLocal());
        }

        if (peerTransportParameters.getInitialMaxStreamDataBidiRemote() > initialMaxStreamDataBidiRemote) {
            log.info("Increasing initial max data from " + initialMaxStreamDataBidiRemote + " to " + peerTransportParameters.getInitialMaxStreamDataBidiRemote());
            maxStreamDataAllowed.entrySet().stream()
                    // Find all client initiated bidirectional streams
                    .filter(entry -> entry.getKey() % 4 == 0)
                    .forEach(entry -> {
                        if (peerTransportParameters.getInitialMaxStreamDataBidiRemote() > entry.getValue()) {
                            maxStreamDataAllowed.put(entry.getKey(), peerTransportParameters.getInitialMaxStreamDataBidiRemote());
                        }
                    });
        }
        else if (peerTransportParameters.getInitialMaxStreamDataBidiRemote() < initialMaxStreamDataBidiRemote) {
            log.error("Ignoring attempt to reduce max data from " + initialMaxStreamDataBidiRemote + " to " + peerTransportParameters.getInitialMaxStreamDataBidiRemote());
        }

        if (peerTransportParameters.getInitialMaxStreamDataUni() > initialMaxStreamDataUni) {
            log.info("Increasing initial max data from " + initialMaxStreamDataUni + " to " + peerTransportParameters.getInitialMaxStreamDataUni());
            maxStreamDataAllowed.entrySet().stream()
                    // Find all client initiated unidirectional streams
                    .filter(entry -> entry.getKey() % 4 == 2)
                    .forEach(entry -> {
                        if (peerTransportParameters.getInitialMaxStreamDataUni() > entry.getValue()) {
                            maxStreamDataAllowed.put(entry.getKey(), peerTransportParameters.getInitialMaxStreamDataUni());
                        }
                    });
        }
        else if (peerTransportParameters.getInitialMaxStreamDataUni() < initialMaxStreamDataUni) {
            log.error("Ignoring attempt to reduce max data from " + initialMaxStreamDataUni + " to " + peerTransportParameters.getInitialMaxStreamDataUni());
        }
    }

    public void register(QuicStream stream, FlowControlUpdateListener listener) {
        streamListeners.put(stream.getStreamId(), listener);
    }

    public void unregister(QuicStream stream) {
        streamListeners.remove(stream.getStreamId());
    }


    public void streamOpened(QuicStream stream) {
        int streamId = stream.getStreamId();
        synchronized (this) {
            if (!maxStreamDataAllowed.containsKey(streamId)) {
                maxStreamDataAllowed.put(streamId, determineInitialMaxStreamData(stream));
                maxStreamDataAssigned.put(streamId, 0L);
            }
            if (streamId > maxOpenedStreamId) {
                maxOpenedStreamId = streamId;
            }
        }
    }

    public void streamClosed(QuicStream stream) {
        int streamId = stream.getStreamId();
        synchronized (this) {
            maxStreamDataAssigned.remove(streamId);
            maxStreamDataAllowed.remove(streamId);
        }
    }

    private long determineInitialMaxStreamData(QuicStream stream) {
        if (stream.isUnidirectional()) {
            return initialMaxStreamDataUni;
        }
        else if (role == Role.Client && stream.isClientInitiatedBidirectional()
                || role == Role.Server && stream.isServerInitiatedBidirectional()) {
            // For the receiver (imposing the limit) the stream is peer-initiated (remote).
            // "This limit applies to newly created bidirectional streams opened by the endpoint that receives
            // the transport parameter."
            return initialMaxStreamDataBidiRemote;
        }
        else if (role == Role.Client && stream.isServerInitiatedBidirectional()
                || role == Role.Server && stream.isClientInitiatedBidirectional()) {
            // For the receiver (imposing the limit), the stream is locally-initiated
            // "This limit applies to newly created bidirectional streams opened by the endpoint that sends the
            // transport parameter."
            return initialMaxStreamDataBidiLocal;
        }
        else {
            throw new ImplementationError();
        }
    }

    /**
     * Returns the maximum possible flow control limit for the given stream, taking into account both stream and connection
     * flow control limits. Note that the returned limit is not yet reserved for use by this stream!
     * @param stream
     * @return
     */
    private long currentStreamCredits(QuicStream stream) {
        int streamId = stream.getStreamId();
        long allowedByStream = maxStreamDataAllowed.get(streamId);
        long maxStreamIncrement = allowedByStream - maxStreamDataAssigned.get(streamId);
        long maxPossibleDataIncrement = maxDataAllowed - maxDataAssigned;
        if (maxStreamIncrement > maxPossibleDataIncrement) {
            maxStreamIncrement = maxPossibleDataIncrement;
        }
        return maxStreamIncrement;
    }

    public void process(MaxDataFrame frame) {
        synchronized (this) {
            // If frames are received out of order, the new max can be smaller than the current value.
            if (frame.getMaxData() > maxDataAllowed) {
                boolean maxDataWasReached = maxDataAllowed == maxDataAssigned;
                maxDataAllowed = frame.getMaxData();
                if (maxDataWasReached) {
                    streamListeners.forEach((streamId, listener) -> {
                        boolean streamWasBlockedByMaxDataOnly = maxStreamDataAssigned.get(streamId) != maxStreamDataAllowed.get(streamId);
                        if (streamWasBlockedByMaxDataOnly) {
                            listener.streamNotBlocked(streamId);
                        }
                    });
                }
            }
        }
    }

    public void process(MaxStreamDataFrame frame) throws TransportError {
        synchronized (this) {
            int streamId = frame.getStreamId();
            long maxStreamData = frame.getMaxData();
            if (maxStreamDataAllowed.containsKey(streamId)) {
                // If frames are received out of order, the new max can be smaller than the current value.
                if (maxStreamData > maxStreamDataAllowed.get(streamId)) {
                    boolean streamWasBlocked = maxStreamDataAssigned.get(streamId).longValue() == maxStreamDataAllowed.get(streamId).longValue()
                            && maxDataAssigned != maxDataAllowed;
                    maxStreamDataAllowed.put(streamId, maxStreamData);
                    if (streamWasBlocked) {
                        streamListeners.get(streamId).streamNotBlocked(streamId);
                    }
                }
            }
            else {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-33#section-19.10
                // "Receiving a MAX_STREAM_DATA frame for a locally-initiated stream that has not yet been created MUST
                //  be treated as a connection error of type STREAM_STATE_ERROR."
                if (locallyInitiated(streamId) && streamId > maxOpenedStreamId) {
                    throw new TransportError(STREAM_STATE_ERROR);
                }
            }
        }
    }

    private boolean locallyInitiated(int streamId) {
        if (role == Role.Client) {
            return streamId % 2 == 0;
        }
        else {
            return streamId % 2 == 1;
        }
    }
}
