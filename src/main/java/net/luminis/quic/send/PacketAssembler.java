/*
 * Copyright © 2020 Peter Doornbosch
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

import net.luminis.quic.AckGenerator;
import net.luminis.quic.EncryptionLevel;
import net.luminis.quic.Version;
import net.luminis.quic.frame.AckFrame;
import net.luminis.quic.frame.PingFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.packet.HandshakePacket;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.packet.ShortHeaderPacket;
import net.luminis.quic.packet.ZeroRttPacket;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Assembles quic packets, based on "send requests" that are previously queued.
 *
 */
public class PacketAssembler {

    protected final static Consumer<QuicFrame> EMPTY_CALLBACK = f -> {};

    protected final Version quicVersion;
    protected final EncryptionLevel level;
    protected final int maxPacketSize;
    protected final SendRequestQueue requestQueue;
    protected final AckGenerator ackGenerator;
    protected long nextPacketNumber;


    public PacketAssembler(Version version, EncryptionLevel level, int maxPacketSize, SendRequestQueue requestQueue, AckGenerator ackGenerator) {
        quicVersion = version;
        this.level = level;
        this.maxPacketSize = maxPacketSize - 3;  // Packet can be 3 bytes larger than estimated size because of unknown packet number length
        this.requestQueue = requestQueue;
        this.ackGenerator = ackGenerator;
    }

    /**
     *
     * @param remainingCwndSize
     * @param sourceConnectionId        can be null when encryption level is 1-rtt; but not for the other levels; can be empty array though
     * @param destinationConnectionId
     * @return
     */
    Optional<SendItem> assemble(int remainingCwndSize, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        int remaining = Integer.min(remainingCwndSize, maxPacketSize);

        QuicPacket packet = createPacket(sourceConnectionId, destinationConnectionId, null);
        Long packetNumber = null;
        List<Consumer<QuicFrame>> callbacks = new ArrayList<>();

        AckFrame ackFrame = null;
        // Check for an explicit ack, i.e. an ack on ack-eliciting packet that cannot be delayed (any longer)
        if (requestQueue.mustSendAck()) {
            requestQueue.getAck();
            if (ackGenerator.hasNewAckToSend()) {
                packetNumber = nextPacketNumber();
                ackFrame = ackGenerator.generateAckForPacket(packetNumber);
                packet.addFrame(ackFrame);
                callbacks.add(EMPTY_CALLBACK);
            }
        }

        if (ackFrame == null && requestQueue.hasRequests()) {
            // If there is no explicit ack, but there is something to send, ack should always be included   // TODO: wrong, only if enough size
            if (ackGenerator.hasAckToSend()) {
                packetNumber = nextPacketNumber();
                ackFrame = ackGenerator.generateAckForPacket(packetNumber);
                packet.addFrame(ackFrame);
                callbacks.add(EMPTY_CALLBACK);
            }
        }

        if (requestQueue.hasProbeWithData()) {
            // Probe is not limited by congestion control
            List<QuicFrame> probeData = requestQueue.getProbe();
            packet.addFrames(probeData);
            return Optional.of(new SendItem(packet));
        }

        int estimatedSize = packet.estimateLength();
        Optional<SendRequest> next;
        while ((next = requestQueue.next(remaining - estimatedSize)).isPresent()) {
            QuicFrame nextFrame = next.get().getFrameSupplier().apply(remaining - estimatedSize);
            if (nextFrame == null) {
                System.out.println("ERROR: supplier does not produce frame!");
                throw new IllegalStateException();
            }
            else if (nextFrame.getBytes().length > remaining - estimatedSize) {
                System.out.println("ERROR: supplier does not produce frame of right (max) size: " + nextFrame.getBytes().length + " > " + (remaining - estimatedSize) + " frame: " + nextFrame);
                throw new IllegalStateException();
            }
            estimatedSize += nextFrame.getBytes().length;
            packet.addFrame(nextFrame);
            callbacks.add(next.get().getLostCallback());
        }

        if (requestQueue.hasProbe() && packet.getFrames().isEmpty()) {
            requestQueue.getProbe();
            packet.addFrame(new PingFrame());
            callbacks.add(EMPTY_CALLBACK);
        }

        if (packet.getFrames().size() > 0) {
            if (packetNumber == null) {
                packetNumber = nextPacketNumber();
            }
            packet.setPacketNumber(packetNumber);
            return Optional.of(new SendItem(packet, createPacketLostCallback(packet, callbacks)));
        }
        else {
            return Optional.empty();
        }
    }

    private long nextPacketNumber() {
        return nextPacketNumber++;
    }

    private Consumer<QuicPacket> createPacketLostCallback(QuicPacket packet, List<Consumer<QuicFrame>> callbacks) {
        if (packet.getFrames().size() != callbacks.size()) {
            throw new IllegalStateException();
        }
        return lostPacket -> {
            for (int i = 0; i < callbacks.size(); i++) {
                if (callbacks.get(i) != EMPTY_CALLBACK) {
                    QuicFrame lostFrame = lostPacket.getFrames().get(i);
                    callbacks.get(i).accept(lostFrame);
                }
            }
        };
    }

    protected QuicPacket createPacket(byte[] sourceConnectionId, byte[] destinationConnectionId, QuicFrame frame) {
        switch (level) {
            case Handshake:
                return new HandshakePacket(quicVersion, sourceConnectionId, destinationConnectionId, frame);
            case App:
                return new ShortHeaderPacket(quicVersion, destinationConnectionId, frame);
            case ZeroRTT:
                return new ZeroRttPacket(quicVersion, sourceConnectionId, destinationConnectionId, frame);
            default:
                throw new RuntimeException();  // programming error
        }
    }
}

