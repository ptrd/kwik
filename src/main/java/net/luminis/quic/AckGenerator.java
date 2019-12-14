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

import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.packet.QuicPacket;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Listens for received packets and generates ack frames for them.
 */
public class AckGenerator {

    private Version quicVersion = Version.getDefault();
    private List<Long> packetsToAcknowledge = new ArrayList<>();
    private boolean newPacketsToAcknowledge;
    private Map<Long, AckFrame> ackSentWithPacket = new HashMap<>();

    public synchronized boolean hasAckToSend() {
        return !packetsToAcknowledge.isEmpty();
    }

    public synchronized boolean hasNewAckToSend() {
        return newPacketsToAcknowledge;
    }

    public synchronized void packetReceived(QuicPacket packet) {
        if (packet.canBeAcked()) {
            packetsToAcknowledge.add(packet.getPacketNumber());
            if (packet.isAckEliciting()) {
                newPacketsToAcknowledge = true;
            }
        }
    }

    /**
     * Process a received AckFrame.
     * @param receivedAck
     * @param encryptionLevel
     */
    public synchronized void process(QuicFrame receivedAck, EncryptionLevel encryptionLevel) {
        // Find max packet number that had an ack sent with it...
        ((AckFrame) receivedAck).getAckedPacketNumbers().stream()
                .filter(pn -> ackSentWithPacket.containsKey(pn))
                .limit(1)
                .forEach(pn -> {
                    // ... and for that max pn, all packets that where acked by it don't need to be acked again.
                    AckFrame ackSent = ackSentWithPacket.get(pn);
                    ackSent.getAckedPacketNumbers().forEach((Long ackedPacket) -> packetsToAcknowledge.remove(ackedPacket));
                });
    }

    /**
     * Generate an AckFrame that will be sent in a packet with the given packet number.
     * @param packetNumber
     * @return
     */
    public synchronized AckFrame generateAckForPacket(long packetNumber) {
        AckFrame ackFrame = new AckFrame(quicVersion, packetsToAcknowledge);
        ackSentWithPacket.put(packetNumber, ackFrame);
        newPacketsToAcknowledge = false;
        return ackFrame;
    }
}

