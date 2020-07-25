/*
 * Copyright © 2019, 2020 Peter Doornbosch
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

import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.PacketInfo;
import net.luminis.quic.packet.QuicPacket;

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
        if (! sentPacket.isAckOnly()) {
            bytesInFlight += sentPacket.getSize();
            log.debug("Bytes in flight increased to " + bytesInFlight);
            if (bytesInFlight > congestionWindow) {
                log.cc("Bytes in flight exceeds congestion window: " + bytesInFlight + " > " + congestionWindow);
            }
            synchronized (lock) {
                lock.notifyAll();
            }
        }
    }

    @Override
    public synchronized void registerAcked(List<? extends PacketInfo> acknowlegdedPackets) {
        int bytesInFlightAcked = acknowlegdedPackets.stream()
                .map(packetInfo -> ((PacketInfo) packetInfo).packet())
                .mapToInt(packet -> packet.getSize())
                .sum();

        if (bytesInFlightAcked > 0) {
            bytesInFlight -= bytesInFlightAcked;
            checkBytesInFlight();
            log.debug("Bytes in flight decreased to " + bytesInFlight + " (" + acknowlegdedPackets.size() + " packets acked)");
            synchronized (lock) {
                lock.notifyAll();
            }
        }
    }

    @Override
    public synchronized void registerLost(List<? extends PacketInfo> lostPackets) {
        long lostBytes = lostPackets.stream()
                .map(packetStatus -> packetStatus.packet())
                .mapToInt(packet -> packet.getSize())
                .sum();
        bytesInFlight -= lostBytes;

        if (lostBytes > 0) {
            checkBytesInFlight();
            log.debug("Bytes in flight decreased to " + bytesInFlight + " (" + lostPackets.size() + " packets lost)");
        }
    }

    @Override
    public synchronized void discard(List<? extends PacketInfo> discardedPackets) {
        long discardedBytes = discardedPackets.stream()
                .map(packetStatus -> packetStatus.packet())
                .mapToInt(packet -> packet.getSize())
                .sum();
        bytesInFlight -= discardedBytes;

        if (discardedBytes > 0) {
            checkBytesInFlight();
            log.debug("Bytes in flight decreased with " + discardedBytes + " to " + bytesInFlight + " (" + discardedPackets.size() + " packets RESET)");
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

    @Override
    public long remainingCwnd() {
        return congestionWindow - bytesInFlight;
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

    private void checkBytesInFlight() {
        if (bytesInFlight < 0) {
            log.error("Inconsistency error in congestion controller; attempt to set bytes in-flight below 0");
            bytesInFlight = 0;
        }
    }
}

