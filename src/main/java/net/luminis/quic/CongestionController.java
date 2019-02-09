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
 * A simplistic static congestion controller, that does not allow more than approx. one packetsize in flight.
 */
public class CongestionController {

    private final Logger log;
    private final Object lock = new Object();

    private int bytesInFlight;
    private int congestionWindow;


    public CongestionController(Logger logger) {
        this.log = logger;
        congestionWindow = 1250;  // i.e. approx 1 max packet size
    }

    public synchronized boolean canSend(QuicPacket packet) {
        return bytesInFlight + packet.getBytes().length < congestionWindow;
    }

    public synchronized void registerAcked(QuicPacket acknowlegdedPacket) {
        bytesInFlight -= acknowlegdedPacket.getBytes().length;
        log.debug("Bytes in flight decreased to " + bytesInFlight);
        synchronized (lock) {
            lock.notifyAll();
        }
    }

    public synchronized void registerInFlight(QuicPacket sentPacket) {
        bytesInFlight += sentPacket.getBytes().length;
        log.debug("Bytes in flight increased to " + bytesInFlight);
        synchronized (lock) {
            lock.notifyAll();
        }
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
