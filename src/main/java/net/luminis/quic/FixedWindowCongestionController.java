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

/**
 * A simplistic congestion controller that has a fixed window size.
 */
public class FixedWindowCongestionController implements CongestionController {

    private final Logger log;
    private final Object lock = new Object();

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-18#section-7.9.1
    // "The RECOMMENDED value is the minimum of 10 * kMaxDatagramSize and max(2* kMaxDatagramSize, 14600))."
    // "kMaxDatagramSize: The RECOMMENDED value is 1200 bytes."
    private static final int initialWindowSize = 10 * 1200;

    private int bytesInFlight;
    private int congestionWindow;


    public FixedWindowCongestionController(Logger logger) {
        this.log = logger;
        congestionWindow = initialWindowSize;
    }

    @Override
    public synchronized boolean canSend(int bytes) {
        return bytesInFlight + bytes < congestionWindow;
    }

    @Override
    public synchronized void registerAcked(QuicPacket acknowlegdedPacket) {
        bytesInFlight -= acknowlegdedPacket.getSize();
        log.debug("Bytes in flight decreased to " + bytesInFlight);
        synchronized (lock) {
            lock.notifyAll();
        }
    }

    @Override
    public synchronized void registerInFlight(QuicPacket sentPacket) {
        bytesInFlight += sentPacket.getSize();
        log.debug("Bytes in flight increased to " + bytesInFlight);
        synchronized (lock) {
            lock.notifyAll();
        }
    }

    @Override
    public void waitForUpdate() throws InterruptedException {
        synchronized (lock) {
            lock.wait();
        }
    }

    @Override
    public void reset() {
        log.debug("Resetting congestion controller.");
        bytesInFlight = 0;
    }
}

