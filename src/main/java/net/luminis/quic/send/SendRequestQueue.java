/*
 * Copyright © 2020, 2021 Peter Doornbosch
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
package net.luminis.quic.send;


import net.luminis.quic.frame.PingFrame;
import net.luminis.quic.frame.QuicFrame;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

public class SendRequestQueue {

    private List<SendRequest> requestQueue = Collections.synchronizedList(new ArrayList<>());
    private List<List<QuicFrame>> probeQueue = Collections.synchronizedList(new ArrayList<>());
    private volatile Instant nextAckTime;
    private volatile boolean cleared;

    public void addRequest(QuicFrame fixedFrame, Consumer<QuicFrame> lostCallback) {
        requestQueue.add(new SendRequest(fixedFrame.getBytes().length, actualMaxSize -> fixedFrame, lostCallback));
    }

    public void addAckRequest() {
        nextAckTime = Instant.now();
    }

    public void addAckRequest(int delay) {
        Instant requestedAckTime = Instant.now().plusMillis(delay);
        if (nextAckTime == null || requestedAckTime.isBefore(nextAckTime)) {
            nextAckTime = requestedAckTime;
        }
    }

    public void addProbeRequest() {
        probeQueue.add(Collections.emptyList());
    }

    public void addProbeRequest(List<QuicFrame> frames) {
        probeQueue.add(frames);
    }

    public boolean hasProbe() {
        return !probeQueue.isEmpty();
    }

    public boolean hasProbeWithData() {
        synchronized (probeQueue) {
            return !probeQueue.isEmpty() && !probeQueue.get(0).isEmpty();
        }
    }

    public List<QuicFrame> getProbe() {
        synchronized (probeQueue) {
            if (hasProbe()) {
                return probeQueue.remove(0);
            }
            else {
                // Even when client first checks for a probe, this might happen due to race condition with clear().
                // (and don't bother to much about the chance of an unnecessary probe)
                return List.of(new PingFrame());
            }
        }
    }

    public boolean mustSendAck() {
        Instant now = Instant.now();
        return nextAckTime != null && (now.isAfter(nextAckTime) || Duration.between(now, nextAckTime).toMillis() < 1);
    }

    public Instant getAck() {
        try {
            return nextAckTime;
        }
        finally {
            nextAckTime = null;
        }
    }

    public Instant nextDelayedSend() {
        return nextAckTime;
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
        requestQueue.add(new SendRequest(estimatedSize, frameSupplier, lostCallback));
    }

    public boolean hasRequests() {
        return !requestQueue.isEmpty();
    }
    
    public Optional<SendRequest> next(int maxFrameLength) {
        if (maxFrameLength < 1) {  // Minimum frame size is 1: some frames (e.g. ping) are just a type field.
            // Forget it
            return Optional.empty();
        }
        for (int i = 0; i < requestQueue.size(); i++) {
            try {
                if (requestQueue.get(i).getEstimatedSize() <= maxFrameLength) {
                    return Optional.of(requestQueue.remove(i));
                }
            }
            catch (java.lang.IndexOutOfBoundsException indexError) {
                if (cleared) {
                    // Caused by concurrent clear, don't bother
                    return Optional.empty();
                }
                else {
                    throw indexError;
                }
            }
        }
        // Couldn't find one.
        return Optional.empty();
    }

    public void clear() {
        cleared = true;
        requestQueue.clear();
        probeQueue.clear();
        nextAckTime = null;
    }
}

