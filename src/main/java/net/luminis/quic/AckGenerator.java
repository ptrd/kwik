/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic;

import net.luminis.quic.ack.Range;
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
    private List<Range> rangesToAcknowledge = new ArrayList<>();
    private boolean newPacketsToAcknowledge;
    private Instant newPacketsToAcknowlegdeSince;
    private Map<Long, AckFrame> ackSentWithPacket = new HashMap<>();
    private int acksNotSend = 0;

    public AckGenerator(PnSpace pnSpace, Sender sender) {
        this.pnSpace = pnSpace;
        this.sender = sender;
    }

    public synchronized boolean hasAckToSend() {
        return !rangesToAcknowledge.isEmpty();
    }

    public synchronized boolean hasNewAckToSend() {
        return newPacketsToAcknowledge;
    }

    public synchronized void packetReceived(QuicPacket packet) {
        if (packet.canBeAcked()) {
            Range.extendRangeList(rangesToAcknowledge, packet.getPacketNumber());
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
     * Process a received AckFrame. If the received ack refers to a (sent) packet that contained acks, it confirms
     * those sent acks are received by the peer so they don't have to be sent ever again.
     *
     * @param receivedAck
     */
    public synchronized void process(QuicFrame receivedAck) {
        // Find max packet number that had an ack sent with it...
        Optional<Long> largestWithAck = ((AckFrame) receivedAck).getAckedPacketNumbers()
                .filter(pn -> ackSentWithPacket.containsKey(pn))
                .findFirst();

        if (largestWithAck.isPresent()) {
            // ... and for that max pn, all packets that where acked by it don't need to be acked again.
            AckFrame latestAcknowledgedAck = ackSentWithPacket.get(largestWithAck.get());
            removeAcknowlegdedRanges(rangesToAcknowledge, latestAcknowledgedAck);

            // And for all earlier sent packets (smaller packet numbers), the sent ack's can be discarded because
            // their ranges are a subset of the ones from the latestAcknowledgedAck and thus are now implicitly acked.
            ackSentWithPacket.keySet().removeIf(key -> key <= largestWithAck.get());
        }
    }

    /**
     * Removes the ranges acked by the given ack from the ranges list.
     * If ranges are not equal but overlap, the range from the list will be replaced by a range that does not contain
     * the common elements, except for the special case when the range list contains the ack range without any of the
     * range bounds to match, because this would lead to more ranges in the list, thus making the ack frame larger and
     * more complex. For example, when the list contains 9..3 and the ack contains 7..5, the list will stay unchanged
     * and not be modified to the longer list 9..8, 4..3.
     * @param rangesToAcknowledge
     * @param ack
     */
    void removeAcknowlegdedRanges(List<Range> rangesToAcknowledge, AckFrame ack) {
        if (rangesToAcknowledge.isEmpty()) {
            return;
        }

        ListIterator<Range> rangeListIterator = rangesToAcknowledge.listIterator();
        ListIterator<Range> ackRangesIterator = ack.getAcknowledgedRanges().listIterator();
        Range currentListRange = rangeListIterator.next();
        while (ackRangesIterator.hasNext()) {
            Range currentAckRange = ackRangesIterator.next();
            while (currentListRange.greaterThan(currentAckRange)) {
                if (rangeListIterator.hasNext()) {
                    currentListRange = rangeListIterator.next();
                } else {
                    return;
                }
            }
            if (currentListRange.lessThan(currentAckRange)) {
                // Ack range not present in list
                continue;
            } else {
                // Ranges overlap.
                if (currentAckRange.contains(currentListRange)) {  // Contains includes equals.
                    rangeListIterator.remove();
                } else if (currentListRange.properlyContains(currentAckRange)) {
                    // Would lead to splitting current range => ignore
                } else {
                    rangeListIterator.set(currentListRange.subtract(currentAckRange));
                }
            }
        }
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
        // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-13.2.1
        // "An endpoint MUST acknowledge all ack-eliciting Initial and Handshake packets immediately"
        if (newPacketsToAcknowlegdeSince != null && pnSpace == PnSpace.App) {
            delay = (int) Duration.between(newPacketsToAcknowlegdeSince, Instant.now()).toMillis();
            if (delay < 0) {
                // WTF. This should be impossible, but it sometimes happen in the interop tests. Maybe related to docker?
                delay = 0;
            }
        }
        if (!rangesToAcknowledge.isEmpty()) {
            // Range list must not be modified during frame initialization (guaranteed by this method being sync'd)
            return Optional.of(new AckFrame(quicVersion, this.rangesToAcknowledge, delay));
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

