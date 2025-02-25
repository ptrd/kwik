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
package tech.kwik.core.send;


import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.frame.PathResponseFrame;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.frame.QuicFrame;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.function.Consumer;
import java.util.function.Function;

public class SendRequestQueue {

    public static final int MAX_QUEUED_PATH_RESPONSE_FRAMES = 256;
    private final Clock clock;
    private final EncryptionLevel encryptionLevel;
    private Deque<SendRequest> requestQueue = new ConcurrentLinkedDeque<>();
    private Deque<List<QuicFrame>> probeQueue = new ConcurrentLinkedDeque<>();
    private final Object ackLock = new Object();
    private Instant nextAckTime;
    private volatile boolean cleared;

    public SendRequestQueue(EncryptionLevel level) {
        this(Clock.systemUTC(), level);
    }

    public SendRequestQueue(Clock clock, EncryptionLevel level) {
        this.clock = clock;
        encryptionLevel = level;
    }

    public void addRequest(QuicFrame fixedFrame, Consumer<QuicFrame> lostCallback) {
        if (fixedFrame instanceof PathResponseFrame) {
            // Defense against Path Challenge DOS attack: prevent number of path response frames that can be queued is unbound.
            long pathResponseFrameCount = requestQueue.stream()
                    .filter(request -> request instanceof FixedFrameSendRequest)
                    .filter(request -> ((FixedFrameSendRequest) request).getFrameType().equals(PathResponseFrame.class))
                    .count();
            if (pathResponseFrameCount >= MAX_QUEUED_PATH_RESPONSE_FRAMES) {
                return;
            }
        }

        requestQueue.addLast(new FixedFrameSendRequest(fixedFrame, lostCallback));
    }

    public void addAckRequest() {
        synchronized (ackLock) {
            nextAckTime = clock.instant();
        }
    }

    public void addAckRequest(int delay) {
        Instant requestedAckTime = clock.instant().plusMillis(delay);
        synchronized (ackLock) {
            if (nextAckTime == null || requestedAckTime.isBefore(nextAckTime)) {
                nextAckTime = requestedAckTime;
            }
        }
    }

    public void addPriorityRequest(QuicFrame fixedFrame, Consumer<QuicFrame> lostCallback) {
        requestQueue.addFirst(new FixedFrameSendRequest(fixedFrame, lostCallback));
    }

    public void addProbeRequest() {
        probeQueue.addLast(Collections.emptyList());
    }

    public void addProbeRequest(List<QuicFrame> frames) {
        probeQueue.addLast(frames);
    }

    public boolean hasProbe() {
        return !probeQueue.isEmpty();
    }

    public boolean hasProbeWithData() {
        List<QuicFrame> firstProbe = probeQueue.peekFirst();
        return firstProbe != null && !firstProbe.isEmpty();
    }

    public List<QuicFrame> getProbe() {
        List<QuicFrame> probe = probeQueue.pollFirst();
        if (probe != null) {
            return probe;
        }
        else {
            // Even when client first checks for a probe, this might happen due to race condition with clear().
            // (and don't bother too much about the chance of an unnecessary probe)
            return List.of(new PingFrame());
        }
    }

    public boolean mustSendAck() {
        Instant now = clock.instant();
        synchronized (ackLock) {
            return nextAckTime != null && (now.isAfter(nextAckTime) || Duration.between(now, nextAckTime).toMillis() < 1);
        }
    }

    /**
     * Check on whether an ack must be sent and promise to do so: if this method returns true the flag that indicates (when)
     * an explicit ack must be sent will be reset, so if the caller does not actually send the ack, the notion it had to be
     * sent will be lost.
     * The reason for this uncommon behaviour is to avoid race conditions: when checking and changing status is not done
     * transactionally, a next change might be lost.
     * @return
     */
    public boolean mustAndWillSendAck() {
        Instant now = clock.instant();
        synchronized (ackLock) {
            boolean must = nextAckTime != null && (now.isAfter(nextAckTime) || Duration.between(now, nextAckTime).toMillis() < 1);
            if (must) {
                nextAckTime = null;
            }
            return must;
        }
    }

    public Instant getAck() {
        synchronized (ackLock) {
            try {
                return nextAckTime;
            } finally {
                nextAckTime = null;
            }
        }
    }

    public Instant nextDelayedSend() {
        synchronized (ackLock) {
            return nextAckTime;
        }
    }

    /**
     * @param frameSupplier
     * @param estimatedSize   The minimum size of the frame that the supplier can produce. When the supplier is
     *                        requested to produce a frame of that size, it must return a frame of the size or smaller.
     *                        This leaves room for the caller to handle uncertainty of how large the frame will be,
     *                        for example due to a var-length int value that may be larger at the moment the frame
     * @param lostCallback
     */
    public void addRequest(Function<Integer, QuicFrame> frameSupplier, int estimatedSize, Consumer<QuicFrame> lostCallback) {
        requestQueue.addLast(new FrameSupplierSendRequest(estimatedSize, frameSupplier, lostCallback));
    }

    public boolean hasRequests() {
        return !requestQueue.isEmpty();
    }
    
    public Optional<SendRequest> next(int maxFrameLength) {
        if (maxFrameLength < 1) {  // Minimum frame size is 1: some frames (e.g. ping) are just a type field.
            // Forget it
            return Optional.empty();
        }

        try {
            for (Iterator<SendRequest> iterator = requestQueue.iterator(); iterator.hasNext(); ) {
                SendRequest next = iterator.next();
                if (next.getEstimatedSize() <= maxFrameLength) {
                    iterator.remove();
                    return Optional.of(next);
                }
            }
            // Couldn't find one.
            return Optional.empty();
        }
        catch (ConcurrentModificationException concurrentModificationException) {
            if (cleared) {
                // Caused by concurrent clear, don't bother
                return Optional.empty();
            }
            else {
                throw concurrentModificationException;
            }
        }
    }

    public void clear() {
        clear(true);
    }

    public void clear(boolean dropAcks) {
        cleared = true;
        requestQueue.clear();
        probeQueue.clear();
        if (dropAcks) {
            synchronized (ackLock) {
                nextAckTime = null;
            }
        }
    }

    public boolean isEmpty() {
        return isEmpty(false);
    }

    public boolean isEmpty(boolean ignoreAcks) {
        if (ignoreAcks) {
            return requestQueue.isEmpty();
        }
        else {
            synchronized (ackLock) {
                return requestQueue.isEmpty() && nextAckTime == null;
            }
        }
    }

    @Override
    public String toString() {
        return "SendRequestQueue[" + encryptionLevel + "]";
    }

}

