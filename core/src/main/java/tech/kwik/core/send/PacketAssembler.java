/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
import tech.kwik.core.cid.ConnectionIdProvider;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.frame.AckFrame;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.frame.RetireConnectionIdFrame;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.packet.HandshakePacket;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.packet.ShortHeaderPacket;
import tech.kwik.core.packet.ZeroRttPacket;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

import static tech.kwik.core.common.EncryptionLevel.App;

/**
 * Assembles QUIC packets for a given encryption level, based on "send requests" that are previously queued.
 * These send requests either contain a frame, or can produce a frame to be sent.
 */
public class PacketAssembler {

    protected final static Consumer<QuicFrame> EMPTY_CALLBACK = f -> {};

    protected final VersionHolder quicVersion;
    protected final EncryptionLevel level;
    protected final SendRequestQueue requestQueue;
    protected final AckGenerator ackGenerator;
    protected final ConnectionIdProvider cidProvider;
    private final PacketNumberGenerator packetNumberGenerator;
    protected long nextPacketNumber;
    private volatile boolean stopping;
    private Consumer<PacketAssembler> finalizerCallback;


    public PacketAssembler(VersionHolder version, EncryptionLevel level, SendRequestQueue requestQueue, AckGenerator ackGenerator,
                           ConnectionIdProvider connectionIdProvider) {
        this(version, level, requestQueue, ackGenerator, connectionIdProvider, new PacketNumberGenerator());
    }

    public PacketAssembler(VersionHolder version, EncryptionLevel level, SendRequestQueue requestQueue, AckGenerator ackGenerator,
                           ConnectionIdProvider connectionIdProvider, PacketNumberGenerator pnGenerator) {
        quicVersion = version;
        this.level = level;
        this.requestQueue = Objects.requireNonNull(requestQueue);
        this.ackGenerator = Objects.requireNonNull(ackGenerator);
        this.cidProvider = Objects.requireNonNull(connectionIdProvider);
        packetNumberGenerator = Objects.requireNonNull(pnGenerator);
    }

    /**
     * Assembles a QUIC packet for the encryption level handled by this instance.
     *
     * @param remainingCwndSize     the maximum size the congestion window allows at this time
     * @param availablePacketSize   the maximum size that is available for the packet
     * @param defaultClientAddress  the client address to use if the queued request does not specify an (alternate) address
     * @return
     */
    Optional<SendItem> assemble(int remainingCwndSize, int availablePacketSize, InetSocketAddress defaultClientAddress) {
        final int available = Integer.min(remainingCwndSize, availablePacketSize);

        // First check for alternate client address (has always priority)
        if (requestQueue.hasAlternateAddressRequest()) {
            assert level == EncryptionLevel.App;
            Optional<SendRequest> request = requestQueue.getAlternateAddressRequest(available);
            if (request.isPresent()) {
                return request.map(sendRequest -> {
                    QuicPacket packet = createPacket(sendRequest.getAlternateAddress());
                    packet.addFrame(sendRequest.getFrame(available));
                    return new SendItem(packet, sendRequest.getAlternateAddress());
                });
            }
        }

        QuicPacket packet = createPacket(defaultClientAddress);
        List<Consumer<QuicFrame>> callbacks = new ArrayList<>();

        AckFrame ackFrame = null;
        // Check for an explicit ack, i.e. an ack on ack-eliciting packet that cannot be delayed (any longer)
        if (requestQueue.mustAndWillSendAck()) {
            if (ackGenerator.hasNewAckToSend()) {
                ackFrame = ackGenerator.generateAck().get();   // Explicit ack cannot disappear by other means than sending it.
                // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-13.2
                // "... packets containing only ACK frames are not congestion controlled ..."
                // So: only check if it fits within available packet space
                if (packet.estimateLength(ackFrame.getFrameLength()) <= availablePacketSize) {
                    packet.addFrame(ackFrame);
                    callbacks.add(EMPTY_CALLBACK);
                    ackGenerator.registerAckSendWithPacket(ackFrame, packet.getPacketNumber());
                }
                else {
                    // If not even a mandatory ack can be added, don't bother about other frames: theoretically there might be frames
                    // that can be fit, but this is very unlikely to happen (because limit packet size is caused by coalescing packets
                    // in one datagram, which will only happen during handshake, when acks are still small) and even then: there
                    // will be a next packet in due time.
                    // However, the ack removed from the queue must be returned
                    requestQueue.addAckRequest();
                    return Optional.empty();
                }
            }
        }

        if (requestQueue.hasProbeWithData()) {
            List<QuicFrame> probeData = requestQueue.getProbe();
            // Probe is not limited by congestion control, but it is limited by max packet size.
            int estimatedSize = packet.estimateLength(probeData.stream().mapToInt(f -> f.getFrameLength()).sum());
            if (estimatedSize > availablePacketSize) {
                QuicFrame probeFrame = new PingFrame();
                if (packet.estimateLength(probeFrame.getFrameLength()) > availablePacketSize) {
                    return Optional.empty();
                }
                probeData = List.of(probeFrame);
            }
            packet.setIsProbe(true);
            packet.addFrames(probeData);
            return Optional.of(new SendItem(packet, defaultClientAddress));
        }

        if (requestQueue.hasRequests()) {
            // Must create packet here, to have an initial estimate of packet header overhead
            int estimatedSize = packet.estimateLength(1000) - 1000;  // Estimate length if large frame would have been added; this will give upper limit of packet overhead.

            while (estimatedSize < available) {
                int proposedSize = available - estimatedSize;
                Optional<SendRequest> next = requestQueue.next(proposedSize);
                if (next.isEmpty()) {
                    // Nothing fits within available space
                    break;
                }
                QuicFrame nextFrame = next.get().getFrame(proposedSize);
                if (nextFrame != null) {
                    if (nextFrame.getFrameLength() > proposedSize) {
                        throw new RuntimeException("supplier does not produce frame of right (max) size: " + nextFrame.getFrameLength() + " > " + (proposedSize) + " frame: " + nextFrame);
                    }

                    estimatedSize += nextFrame.getFrameLength();
                    packet.addFrame(nextFrame);
                    callbacks.add(next.get().getLostCallback());

                    if (nextFrame instanceof RetireConnectionIdFrame) {
                        // In case the connection id has changed after the packet was created, make sure the new cid is
                        // used, as the old might have been retired and subject of this RetireConnectionIdFrame.
                        byte[] currentCid = cidProvider.getPeerConnectionId(defaultClientAddress);
                        if (! Arrays.equals(currentCid, packet.getDestinationConnectionId())) {
                            // For the time being, log this so we can validate this race condition has been fixed.
                            System.out.println("Refreshing CID, as packets contains " + nextFrame
                                    + "(changed from " + Arrays.toString(packet.getDestinationConnectionId())
                                    + " to " + Arrays.toString(currentCid) + ")");
                            // TODO: take into account that new cid can be of different length than old cid, which will change packet header size and thus the max size of the packet.
                            packet = clonePacket(packet, currentCid);
                        }
                    }
                }
            }
        }

        if (requestQueue.hasProbe() && packet.getFrames().isEmpty()) {
            requestQueue.getProbe();
            packet.setIsProbe(true);
            packet.addFrame(new PingFrame());
            callbacks.add(EMPTY_CALLBACK);
        }

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2.4
        // "A receiver that sends only non-ack-eliciting packets, such as ACK frames, might not receive an acknowledgment
        //  for a long period of time. (...) In such a case, a receiver could send a PING (...) to elicit an ACK from the peer."
        if (packet.isAckOnly() && level == App) {
            if (ackGenerator.wantsAckFromPeer()) {
                packet.addFrame(new PingFrame());
                callbacks.add(EMPTY_CALLBACK);
            }
        }
        Optional<SendItem> assembledItem;
        if (packet.getFrames().isEmpty()) {
            // Nothing could be added, discard packet and mark packet number as not used
            restorePacketNumber();
            assembledItem = Optional.empty();
        }
        else {
            assembledItem = Optional.of(new SendItem(packet, createPacketLostCallback(packet, callbacks), defaultClientAddress));
        }

        if (stopping && requestQueue.isEmpty(false)) {
            if (finalizerCallback != null) {
                finalizerCallback.accept(this);
            }
        }

        return assembledItem;
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

    protected QuicPacket createPacket(InetSocketAddress clientAddress) {
        Version version = quicVersion.getVersion();
        byte[] destinationConnectionId = cidProvider.getPeerConnectionId(clientAddress);

        QuicPacket packet;
        switch (level) {
            case Handshake:
                packet = new HandshakePacket(version, cidProvider.getInitialConnectionId(), destinationConnectionId, null);
                break;
            case App:
                packet = new ShortHeaderPacket(version, destinationConnectionId);
                break;
            case ZeroRTT:
                packet = new ZeroRttPacket(version, cidProvider.getInitialConnectionId(), destinationConnectionId, (QuicFrame) null);
                break;
            default:
                throw new RuntimeException();  // programming error
        }
        packet.setPacketNumber(nextPacketNumber());
        return packet;
    }

    protected QuicPacket clonePacket(QuicPacket original, byte[] newDestinationConnectionId) {
        Version version = original.getVersion();

        QuicPacket clone;
        switch (level) {
            case Handshake:
                clone = new HandshakePacket(version, cidProvider.getInitialConnectionId(), newDestinationConnectionId, null);
                break;
            case App:
                clone = new ShortHeaderPacket(version, newDestinationConnectionId);
                break;
            case ZeroRTT:
                clone = new ZeroRttPacket(version, cidProvider.getInitialConnectionId(), newDestinationConnectionId, (QuicFrame) null);
                break;
            default:
                throw new RuntimeException();  // programming error
        }
        for (QuicFrame frame: original.getFrames()) {
            clone.addFrame(frame);
        }
        clone.setPacketNumber(original.getPacketNumber());
        return clone;
    }

    public void stop(Consumer<PacketAssembler> finalizer) {
        this.finalizerCallback = finalizer;
        requestQueue.clear(false);
        stopping = true;
    }

    @Override
    public String toString() {
        return "PacketAssembler[" + level + "]";
    }
}

