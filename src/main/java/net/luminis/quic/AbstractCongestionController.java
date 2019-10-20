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

import java.util.List;

public class AbstractCongestionController implements CongestionController {

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-23#appendix-B.1
    // "The RECOMMENDED value is the minimum of 10 * kMaxDatagramSize and max(2* kMaxDatagramSize, 14600))."
    // "kMaxDatagramSize: The RECOMMENDED value is 1200 bytes."
    protected static final int initialWindowSize = 10 * 1200;

    protected final Logger log;
    private final Object lock = new Object();
    protected volatile long bytesInFlight;
    protected volatile long congestionWindow;

    public AbstractCongestionController(Logger logger) {
        this.log = logger;
        congestionWindow = initialWindowSize;
    }

    @Override
    public synchronized void registerInFlight(QuicPacket sentPacket) {
        if (! sentPacket.getFrames().stream().allMatch(frame -> frame instanceof AckFrame)) {
            bytesInFlight += sentPacket.getSize();
            log.debug("Bytes in flight increased to " + bytesInFlight);
            synchronized (lock) {
                lock.notifyAll();
            }
        }
    }

    @Override
    public synchronized void registerAcked(List<? extends PacketInfo> acknowlegdedPackets) {
        int bytesInFlightAcked = acknowlegdedPackets.stream()
                .map(packetInfo -> ((PacketInfo) packetInfo).packet)
                .filter(ackedPacket -> !ackedPacket.getFrames().stream().allMatch(frame -> frame instanceof AckFrame))
                .mapToInt(packet -> packet.getSize())
                .sum();

        if (bytesInFlightAcked > 0) {
            bytesInFlight -= bytesInFlightAcked;
            log.debug("Bytes in flight decreased to " + bytesInFlight);
            synchronized (lock) {
                lock.notifyAll();
            }
        }
    }

    @Override
    public void registerLost(List<? extends PacketInfo> lostPackets) {
        long lostBytes = lostPackets.stream()
                .map(packetStatus -> packetStatus.packet)
                .filter(lostPacket -> !lostPacket.getFrames().stream().allMatch(frame -> frame instanceof AckFrame))
                .mapToInt(packet -> packet.getSize())
                .sum();
        bytesInFlight -= lostBytes;

        if (lostBytes > 0) {
            log.debug("Bytes in flight decreased to " + bytesInFlight);
        }
    }

    public synchronized boolean canSend(int bytes) {
        return bytesInFlight + bytes < congestionWindow;
    }

    public long getBytesInFlight() {
        return bytesInFlight;
    }

    public long getWindowSize() {
        return congestionWindow;
    }

    public void waitForUpdate() throws InterruptedException {
        synchronized (lock) {
            lock.wait();
        }
    }

    public void reset() {
        log.debug("Resetting congestion controller.");
        bytesInFlight = 0;
    }

}

