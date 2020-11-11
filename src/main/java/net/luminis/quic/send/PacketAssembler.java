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
 * Assembles QUIC packets for a given encryption level, based on "send requests" that are previously queued.
 * These send requests either contain a frame, or can produce a frame to be sent.
 */
public class PacketAssembler {

    protected final static Consumer<QuicFrame> EMPTY_CALLBACK = f -> {};

    protected final Version quicVersion;
    protected final EncryptionLevel level;
    protected final int maxPacketSize;
    protected final SendRequestQueue requestQueue;
    protected final AckGenerator ackGenerator;
    private final PacketNumberGenerator packetNumberGenerator;
    protected long nextPacketNumber;


    public PacketAssembler(Version version, EncryptionLevel level, int maxPacketSize, SendRequestQueue requestQueue, AckGenerator ackGenerator) {
        this(version, level, maxPacketSize, requestQueue, ackGenerator, new PacketNumberGenerator());
    }

    public PacketAssembler(Version version, EncryptionLevel level, int maxPacketSize, SendRequestQueue requestQueue, AckGenerator ackGenerator, PacketNumberGenerator pnGenerator) {
        quicVersion = version;
        this.level = level;
        this.maxPacketSize = maxPacketSize - 3;  // Packet can be 3 bytes larger than estimated size because of unknown packet number length
        this.requestQueue = requestQueue;
        this.ackGenerator = ackGenerator;
        packetNumberGenerator = pnGenerator;
    }

    /**
     * Assembles a QUIC packet for the encryption level handled by this instance.
     * @param remainingCwndSize
     * @param availablePacketSize
     * @param sourceConnectionId        can be null when encryption level is 1-rtt; but not for the other levels; can be empty array though
     * @param destinationConnectionId
     * @return
     */
    Optional<SendItem> assemble(int remainingCwndSize, int availablePacketSize, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        final int available = Integer.min(remainingCwndSize, maxPacketSize);

        Optional<QuicPacket> packet = Optional.empty();
        List<Consumer<QuicFrame>> callbacks = new ArrayList<>();

        AckFrame ackFrame = null;
        // Check for an explicit ack, i.e. an ack on ack-eliciting packet that cannot be delayed (any longer)
        if (requestQueue.mustSendAck()) {
            if (ackGenerator.hasNewAckToSend()) {
                packet = packet.or(() -> Optional.of(createPacket(sourceConnectionId, destinationConnectionId, null)));
                ackFrame = ackGenerator.generateAck().get();   // Explicit ack cannot disappear by other means than sending it.
                // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-13.2
                // "... packets containing only ACK frames are not congestion controlled ..."
                // So: only check if it fits within available packet space
                if (packet.get().estimateLength() + ackFrame.getBytes().length <= availablePacketSize) {
                    packet.get().addFrame(ackFrame);
                    callbacks.add(EMPTY_CALLBACK);
                    ackGenerator.registerAckSendWithPacket(ackFrame, packet.get().getPacketNumber());
                    requestQueue.getAck();
                }
                else {
                    // If not even a mandatory ack can be added, don't bother about other frames: theoretically there might be frames
                    // that can be fit, but this is very unlikely to happen (because limit packet size is caused by coalescing packets
                    // in one datagram, which will only happen during handshake, when acks are still small) and even then: there
                    // will be a next packet in due time.
                    return Optional.empty();
                }
            }
        }

        int optionalAckSize = 0;
        if (ackFrame == null && requestQueue.hasRequests()) {
            // If there is no explicit ack, but there is something to send, ack should be included if possible
            if (ackGenerator.hasAckToSend()) {
                packet = packet.or(() -> Optional.of(createPacket(sourceConnectionId, destinationConnectionId, null)));
                ackFrame = ackGenerator.generateAck().orElse(null);
                if (ackFrame != null) {
                    optionalAckSize = ackFrame.getBytes().length;
                }
            }
        }

        if (requestQueue.hasProbeWithData()) {
            // Probe is not limited by congestion control
            List<QuicFrame> probeData = requestQueue.getProbe();
            // But it is limited by max packet length
            if (probeData.stream().mapToInt(f -> f.getBytes().length).sum() > availablePacketSize) {
                probeData = List.of(new PingFrame());
            }
            packet = packet.or(() -> Optional.of(createPacket(sourceConnectionId, destinationConnectionId, null)));
            packet.get().setIsProbe(true);
            packet.get().addFrames(probeData);
            return Optional.of(new SendItem(packet.get()));
        }

        if (requestQueue.hasRequests()) {
            // Must create packet here, to have an initial estimate of packet header overhead
            packet = packet.or(() -> Optional.of(createPacket(sourceConnectionId, destinationConnectionId, null)));
            int estimatedSize = packet.get().estimateLength();

            while (estimatedSize < available) {
                // First try to find a frame that will leave space for optional frame (if any)
                int proposedSize = available - estimatedSize - optionalAckSize;
                Optional<SendRequest> next = requestQueue.next(proposedSize);
                if (next.isEmpty() && optionalAckSize > 0) {
                    // The optional ack does not fit, try without
                    proposedSize = available - estimatedSize;
                    next = requestQueue.next(proposedSize);
                }
                if (next.isEmpty()) {
                    // Nothing fits within available space
                    break;
                }
                QuicFrame nextFrame = next.get().getFrameSupplier().apply(proposedSize);
                if (nextFrame != null) {
                    if (nextFrame.getBytes().length > proposedSize) {
                        throw new RuntimeException("supplier does not produce frame of right (max) size: " + nextFrame.getBytes().length + " > " + (proposedSize) + " frame: " + nextFrame);
                    }

                    estimatedSize += nextFrame.getBytes().length;
                    packet.get().addFrame(nextFrame);
                    callbacks.add(next.get().getLostCallback());

                    // If there was an optional ack (which was not added yet)...
                    if (optionalAckSize > 0 && estimatedSize + optionalAckSize < available) {
                        // ..., add it now (now that it is sure there will be at least one non-ack frame)
                        packet.get().addFrame(ackFrame);
                        callbacks.add(EMPTY_CALLBACK);
                        ackGenerator.registerAckSendWithPacket(ackFrame, packet.get().getPacketNumber());
                        estimatedSize += ackFrame.getBytes().length;
                        // Adding once will do ;-)
                        optionalAckSize = 0;
                    }
                }
            }
            if (packet.get().getFrames().isEmpty()) {
                // Nothing could be added, discard packet and mark packet number as not used
                packet = Optional.empty();
                restorePacketNumber();
            }
        }

        if (requestQueue.hasProbe() && packet.isEmpty()) {
            packet = packet.or(() -> Optional.of(createPacket(sourceConnectionId, destinationConnectionId, null)));
            requestQueue.getProbe();
            packet.get().setIsProbe(true);
            packet.get().addFrame(new PingFrame());
            callbacks.add(EMPTY_CALLBACK);
        }

        return packet.map(p -> new SendItem(p, createPacketLostCallback(p, callbacks)));
    }

    protected long nextPacketNumber() {
        return packetNumberGenerator.nextPacketNumber();
    }

    protected void restorePacketNumber() {
        packetNumberGenerator.restorePacketNumber();
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
        QuicPacket packet;
        switch (level) {
            case Handshake:
                packet = new HandshakePacket(quicVersion, sourceConnectionId, destinationConnectionId, frame);
                break;
            case App:
                packet = new ShortHeaderPacket(quicVersion, destinationConnectionId, frame);
                break;
            case ZeroRTT:
                packet = new ZeroRttPacket(quicVersion, sourceConnectionId, destinationConnectionId, frame);
                break;
            default:
                throw new RuntimeException();  // programming error
        }
        packet.setPacketNumber(nextPacketNumber());
        return packet;
    }
}

