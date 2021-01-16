/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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
import net.luminis.quic.send.Sender;

import java.time.Duration;
import java.time.Instant;
import java.util.*;


/**
 * Listens for received packets and generates ack frames for them.
 */
public class AckGenerator {

    private final Version quicVersion = Version.getDefault();
    private final PnSpace pnSpace;
    private final Sender sender;
    private List<Long> packetsToAcknowledge = new ArrayList<>();
    private boolean newPacketsToAcknowledge;
    private Instant newPacketsToAcknowlegdeSince;
    private Map<Long, AckFrame> ackSentWithPacket = new HashMap<>();
    private int acksNotSend = 0;

    public AckGenerator(PnSpace pnSpace, Sender sender) {
        this.pnSpace = pnSpace;
        this.sender = sender;
    }

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
                if (newPacketsToAcknowlegdeSince == null) {
                    newPacketsToAcknowlegdeSince = Instant.now();
                }
                if (pnSpace != PnSpace.App) {
                    sender.sendAck(pnSpace, 0);
                }
                else {
                    // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-13.2.2
                    // "A receiver SHOULD send an ACK frame after receiving at least two ack-eliciting packets."
                    int ackFrequency = 2;

                    acksNotSend++;
                    if (acksNotSend >= ackFrequency) {
                        sender.sendAck(pnSpace, 0);
                        acksNotSend = 0;
                    }
                    else {
                        // Default max ack delay is 25, use 20 to give some slack for timing issues
                        sender.sendAck(pnSpace, 20);
                    }
                }
            }
        }
    }

    /**
     * Process a received AckFrame.
     * @param receivedAck
     */
    public synchronized void process(QuicFrame receivedAck) {
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
    public synchronized Optional<AckFrame> generateAckForPacket(long packetNumber) {
        Optional<AckFrame> ackFrame = generateAck();
        if (ackFrame.isPresent()) {
            registerAckSendWithPacket(ackFrame.get(), packetNumber);
        }
        return ackFrame;
    }

    public synchronized Optional<AckFrame> generateAck() {
        int delay = 0;
        if (newPacketsToAcknowlegdeSince != null) {
            delay = (int) Duration.between(newPacketsToAcknowlegdeSince, Instant.now()).toMillis();
            if (delay < 0) {
                // WTF. This should be impossible, but it sometimes happen in the interop tests. Maybe related to docker?
                delay = 0;
            }
        }
        List<Long> packetsToAck = this.packetsToAcknowledge;
        if (!packetsToAck.isEmpty()) {
            return Optional.of(new AckFrame(quicVersion, this.packetsToAcknowledge, delay));
        }
        else {
            return Optional.empty();
        }
    }

    public synchronized void registerAckSendWithPacket(AckFrame ackFrame, long packetNumber) {
        ackSentWithPacket.put(packetNumber, ackFrame);
        newPacketsToAcknowledge = false;
        newPacketsToAcknowlegdeSince = null;
        acksNotSend = 0;
    }
}

