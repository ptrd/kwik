/*
 * Copyright © 2024, 2025 Peter Doornbosch
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

import net.luminis.quic.frame.StreamFrame;

import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Buffers data that needs to be retransmitted, and recreates new StreamFrames from it if necessary.
 * Due to changes in available packet length, an existing (earlier transmitted) StreamFrame may be too big to fit in a
 * packet at the time of retransmit, in which case the data to retransmit must be "re-framed".
 */
public class RetransmitBuffer {

    private Queue<StreamFrame> data;

    public RetransmitBuffer() {
        data = new ConcurrentLinkedQueue<>();
    }

    public void add(StreamFrame frameToRetransmit) {
        data.add(frameToRetransmit);
    }

    public StreamFrame getFrameToRetransmit(int maxFrameSize) {
        if (!data.isEmpty()) {
            StreamFrame frame = data.poll();
            if (frame.getFrameLength() <= maxFrameSize) {
                return frame;
            }
            else {
                // It's too big, split it in two
                int excessLength = frame.getFrameLength() - maxFrameSize;
                int dataLengthFirstFrame = frame.getLength() - excessLength;
                StreamFrame first = new StreamFrame(frame.getStreamId(), frame.getOffset(),
                        frame.getStreamData(), 0, dataLengthFirstFrame, false);
                StreamFrame second = new StreamFrame(frame.getStreamId(), frame.getOffset() + first.getLength(),
                        frame.getStreamData(), first.getLength(), frame.getLength() - first.getLength(), frame.isFinal());
                data.add(second);
                return first;
            }
        }
        else {
            return null;
        }
    }

    public boolean hasDataToRetransmit() {
        return !data.isEmpty();
    }
}
