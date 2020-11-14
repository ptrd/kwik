/*
 * Copyright © 2020 Peter Doornbosch
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
import net.luminis.quic.frame.MaxStreamsFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.frame.StreamFrame;
import net.luminis.quic.log.Logger;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;


public class StreamManager {

    private final Map<Integer, QuicStream> streams;
    private final Version quicVersion;
    private final QuicConnectionImpl connection;
    private FlowControl flowController;
    private final Logger log;
    private int nextStreamId;
    private Consumer<QuicStream> serverStreamCallback;
    private Long maxStreamsBidi;
    private Long maxStreamsUni;
    private final Semaphore openBidirectionalStreams;
    private final Semaphore openUnidirectionalStreams;

    public StreamManager(QuicConnectionImpl quicConnection, Logger log) {
        this.connection = quicConnection;
        this.log = log;
        quicVersion = Version.getDefault();
        streams = new ConcurrentHashMap<>();
        openBidirectionalStreams = new Semaphore(0);
        openUnidirectionalStreams = new Semaphore(0);
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
                (quicVersion, streamId, connection, flowController, logger) -> new QuicStream(quicVersion, streamId, connection, flowController, logger));
    }

    private  QuicStream createStream(boolean bidirectional, long timeout, TimeUnit unit, QuicStreamSupplier streamFactory) throws TimeoutException {
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

        int streamId = generateClientStreamId(bidirectional);
        QuicStream stream = streamFactory.apply(quicVersion, streamId, connection, flowController, log);
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

    private synchronized int generateClientStreamId(boolean bidirectional) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-2.1:
        // "0x0  | Client-Initiated, Bidirectional"
        int id = (nextStreamId << 2) + 0x00;
        if (! bidirectional) {
            // "0x2  | Client-Initiated, Unidirectional |"
            id += 0x02;
        }
        nextStreamId++;
        return id;
    }

    // TODO: inject FlowController in constructor (requires change in FlowController itself)
    public void setFlowController(FlowControl flowController) {
        this.flowController = flowController;
    }

    public void process(StreamFrame frame) {
        int streamId = frame.getStreamId();
        QuicStream stream = streams.get(streamId);
        if (stream != null) {
            stream.add(frame);
        }
        else {
            if (streamId % 2 == 1) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-2.1
                // "servers initiate odd-numbered streams"
                log.info("Receiving data for server-initiated stream " + streamId);
                stream = new QuicStream(quicVersion, streamId, connection, null, log);
                streams.put(streamId, stream);
                stream.add(frame);
                if (serverStreamCallback != null) {
                    serverStreamCallback.accept(stream);
                }
            }
            else {
                log.error("Receiving frame for non-existant stream " + streamId);
            }
        }
    }

    public synchronized void process(MaxStreamsFrame frame, PnSpace pnSpace, Instant timeReceived) {
        if (frame.isAppliesToBidirectional()) {
            if (frame.getMaxStreams() > maxStreamsBidi) {
                int increment = (int) (frame.getMaxStreams() - maxStreamsBidi);
                log.debug("increased max bidirectional streams with " + increment + " to " + frame.getMaxStreams());
                maxStreamsBidi = frame.getMaxStreams();
                openBidirectionalStreams.release(increment);
            }
        }
        else {
            if (frame.getMaxStreams() > maxStreamsUni) {
                int increment = (int) (frame.getMaxStreams() - maxStreamsUni);
                log.debug("increased max unidirectional streams with " + increment + " to " + frame.getMaxStreams());
                maxStreamsUni = frame.getMaxStreams();
                openUnidirectionalStreams.release(increment);
            }
        }
    }

    public void abortAll() {
        streams.values().stream().forEach(s -> s.abort());
    }

    public void setServerStreamCallback(Consumer<QuicStream> streamProcessor) {
        serverStreamCallback = streamProcessor;
    }

    public synchronized void setInitialMaxStreamsBidi(long initialMaxStreamsBidi) {
        if (maxStreamsBidi == null || initialMaxStreamsBidi >= maxStreamsBidi) {
            log.debug("Initial max bidirectional stream: " + initialMaxStreamsBidi);
            maxStreamsBidi = initialMaxStreamsBidi;
            if (initialMaxStreamsBidi > Integer.MAX_VALUE) {
                log.error("Server initial max streams bidirectional is larger than supported; limiting to " + Integer.MAX_VALUE);
                initialMaxStreamsBidi = Integer.MAX_VALUE;
            }
            openBidirectionalStreams.release((int) initialMaxStreamsBidi);
        }
        else {
            log.error("Attempt to reduce value of initial_max_streams_bidi from " + maxStreamsBidi + " to " + initialMaxStreamsBidi + "; ignoring.");
        }
    }

    public synchronized void setInitialMaxStreamsUni(long initialMaxStreamsUni) {
        if (maxStreamsUni == null || initialMaxStreamsUni >= maxStreamsUni) {
            log.debug("Initial max unidirectional stream: " + initialMaxStreamsUni);
            maxStreamsUni = initialMaxStreamsUni;
            if (initialMaxStreamsUni > Integer.MAX_VALUE) {
                log.error("Server initial max streams unirectional is larger than supported; limiting to " + Integer.MAX_VALUE);
                initialMaxStreamsUni = Integer.MAX_VALUE;
            }
            openUnidirectionalStreams.release((int) initialMaxStreamsUni);
        }
        else {
            log.error("Attempt to reduce value of initial_max_streams_uni from " + maxStreamsUni + " to " + initialMaxStreamsUni + "; ignoring.");
        }
    }

    public long getMaxBidirectionalStreams() {
        return maxStreamsBidi;
    }

    public long getMaxUnirectionalStreams() {
        return maxStreamsUni;
    }

    interface QuicStreamSupplier {
        QuicStream apply(Version quicVersion, int streamId, QuicConnectionImpl connection, FlowControl flowController, Logger log);
    }
}

