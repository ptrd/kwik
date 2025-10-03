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
import tech.kwik.core.ack.GlobalAckGenerator;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.frame.PathChallengeFrame;
import tech.kwik.core.frame.PathResponseFrame;
import tech.kwik.core.impl.VersionHolder;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static tech.kwik.core.common.EncryptionLevel.Handshake;
import static tech.kwik.core.common.EncryptionLevel.Initial;
import static tech.kwik.core.common.EncryptionLevel.ZeroRTT;

/**
 * Assembles QUIC packets for sending.
 */
public class GlobalPacketAssembler {

    private SendRequestQueue[] sendRequestQueue;
    private volatile PacketAssembler[] packetAssembler = new PacketAssembler[EncryptionLevel.values().length];
    private volatile EncryptionLevel[] enabledLevels;


    public GlobalPacketAssembler(VersionHolder quicVersion, SendRequestQueue[] sendRequestQueues, GlobalAckGenerator globalAckGenerator) {
        this.sendRequestQueue = sendRequestQueues;

        PacketNumberGenerator appSpacePnGenerator = new PacketNumberGenerator();

        Arrays.stream(EncryptionLevel.values()).forEach(level -> {
            int levelIndex = level.ordinal();
            AckGenerator ackGenerator =
                    (level != ZeroRTT)?
                            globalAckGenerator.getAckGenerator(level.relatedPnSpace()):
                            // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-17.2.3
                            // "... a client cannot send an ACK frame in a 0-RTT packet, ..."
                            new NullAckGenerator();
            switch (level) {
                case ZeroRTT:
                case App:
                    packetAssembler[levelIndex] = new PacketAssembler(quicVersion, level, sendRequestQueue[levelIndex], ackGenerator, appSpacePnGenerator);
                    break;
                case Initial:
                    packetAssembler[levelIndex] = new InitialPacketAssembler(quicVersion, sendRequestQueue[levelIndex], ackGenerator);
                    break;
                default:
                    packetAssembler[levelIndex] = new PacketAssembler(quicVersion, level, sendRequestQueue[levelIndex], ackGenerator);
            }
        });

        enabledLevels = new EncryptionLevel[] { Initial, ZeroRTT, Handshake };
    }

    /**
     * Assembles packets for sending in one datagram. The total size of the QUIC packets returned will never exceed
     * max packet size and for packets not containing probes, it will not exceed the remaining congestion window size.
     * @param remainingCwndSize
     * @param maxDatagramSize
     * @param sourceConnectionId
     * @param destinationConnectionId
     * @return
     */
    public List<SendItem> assemble(int remainingCwndSize, int maxDatagramSize, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        List<SendItem> packets = new ArrayList<>();
        int size = 0;
        boolean hasInitial = false;
        boolean hasPathChallengeOrResponse = false;

        int minPacketSize = 19 + destinationConnectionId.length;  // Computed for short header packet
        int remaining = Integer.min(remainingCwndSize, maxDatagramSize);

        for (EncryptionLevel level: enabledLevels) {
            PacketAssembler assembler = this.packetAssembler[level.ordinal()];
            if (assembler != null) {
                Optional<SendItem> item = assembler.assemble(remaining, maxDatagramSize - size, sourceConnectionId, destinationConnectionId);
                if (item.isPresent()) {
                    packets.add(item.get());
                    int packetSize = item.get().getPacket().estimateLength(0);
                    size += packetSize;
                    remaining -= packetSize;
                    if (level == Initial) {
                        hasInitial = true;
                    }
                    if (item.get().getPacket().getFrames().stream().anyMatch(f -> f instanceof PathChallengeFrame || f instanceof PathResponseFrame)) {
                        hasPathChallengeOrResponse = true;
                    }
                }
                if (remaining < minPacketSize && (maxDatagramSize - size) < minPacketSize) {
                    // Trying a next level to produce a packet is useless
                    break;
                }
            }
        }

        if (hasInitial && size < 1200) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1
            // "A client MUST expand the payload of all UDP datagrams carrying Initial packets to at least the smallest
            //  allowed maximum datagram size of 1200 bytes by adding PADDING frames to the Initial packet or by coalescing
            //  the Initial packet; see Section 12.2."
            // "Similarly, a server MUST expand the payload of all UDP datagrams carrying ack-eliciting Initial packets
            //  to at least the smallest allowed maximum datagram size of 1200 bytes."
            size += addPadding(packets, size, 1200);
        }

        if (hasPathChallengeOrResponse && size < 1200) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.1
            // "An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to at least the smallest allowed
            //  maximum datagram size of 1200 bytes, unless the anti-amplification limit for the path does not permit
            //  sending a datagram of this size."
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.2
            // "An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame to at least the smallest allowed
            //  maximum datagram size of 1200 bytes."
            // "However, an endpoint MUST NOT expand the datagram containing the PATH_RESPONSE if the resulting data
            //  exceeds the anti-amplification limit."
            size += addPadding(packets, size, Integer.min(1200, maxDatagramSize));
        }

        return packets;
    }

    protected int addPadding(List<SendItem> packets, int currentEstimatedSize, int requiredMinimumSize) {
        assert packets.size() > 0;
        final int proposedPadding = requiredMinimumSize - currentEstimatedSize;

        int expectedSizeWithPadding =
                // It doesn't matter to which packet the padding is added, take the first (that is guaranteed to exist)
                packets.get(0).getPacket().estimateLength(proposedPadding) +
                packets.stream()  // And add the size of the coalesced packets (if any)
                        .skip(1)
                        .map(item -> item.getPacket())
                        .mapToInt(p -> p.estimateLength(0))
                        .sum();

        int requiredPadding;
        if (expectedSizeWithPadding > requiredMinimumSize) {
            // Can happen due to padding causing the length field of a long header packet to increase (by 1)
            requiredPadding = proposedPadding - (expectedSizeWithPadding - requiredMinimumSize);
        }
        else if (expectedSizeWithPadding < requiredMinimumSize) {
            // Can happen with very small packets, that already had padding to have minimum size (required by AEAD encryption):
            // when more padding is added, the "initial" padding is no longer needed, causing the packet to shrink
            requiredPadding = proposedPadding + (requiredMinimumSize - expectedSizeWithPadding);
        }
        else {
            requiredPadding = proposedPadding;
        }

        if (requiredPadding > 0) {
            packets.stream()
                    .map(item -> item.getPacket())
                    .findFirst()
                    // It doesn't matter to which packet the padding is added, take the first (that is guaranteed to exist)
                    .ifPresent(packet -> packet.addFrame(new Padding(requiredPadding)));
            return requiredPadding;
        }
        else {
            return 0;
        }
    }

    public Optional<Instant> nextDelayedSendTime() {
        return Arrays.stream(enabledLevels)
                .map(level -> sendRequestQueue[level.ordinal()])
                .map(q -> q.nextDelayedSend())
                .filter(Objects::nonNull)     // Filter after mapping because value can become null during iteration
                .findFirst();
    }

    public void stop(PnSpace pnSpace) {
        packetAssembler[pnSpace.relatedEncryptionLevel().ordinal()].stop(assembler -> {
            packetAssembler[pnSpace.relatedEncryptionLevel().ordinal()] = null;
        });
    }

    public void setInitialToken(byte[] token) {
        ((InitialPacketAssembler) packetAssembler[Initial.ordinal()]).setInitialToken(token);
    }

    public void enableAppLevel() {
        enabledLevels = EncryptionLevel.values();
    }

}
