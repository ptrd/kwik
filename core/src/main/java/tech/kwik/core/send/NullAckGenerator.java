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

import tech.kwik.core.ack.AckGenerator;
import tech.kwik.core.frame.AckFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.packet.QuicPacket;

import java.util.Optional;

/**
 * AckGenerator that does nothing ("Null Pattern")
 */
public class NullAckGenerator extends AckGenerator {

    public NullAckGenerator() {
        super(null, null, null);
    }

    @Override
    public synchronized boolean hasAckToSend() {
        return false;
    }

    @Override
    public synchronized boolean hasNewAckToSend() {
        return false;
    }

    @Override
    public synchronized void packetReceived(QuicPacket packet) {
    }

    @Override
    public synchronized void process(QuicFrame receivedAck) {
    }

    @Override
    public synchronized Optional<AckFrame> generateAckForPacket(long packetNumber) {
        throw new IllegalStateException();
    }

    public boolean wantsAckFromPeer() {
        return false;
    }
}
