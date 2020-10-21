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

import net.luminis.quic.*;
import net.luminis.quic.frame.Padding;
import net.luminis.quic.frame.PathChallengeFrame;
import net.luminis.quic.frame.PathResponseFrame;
import net.luminis.quic.packet.InitialPacket;

import java.util.*;

/**
 * Assembles QUIC packets for sending.
 */
public class GlobalPacketAssembler {

    private SendRequestQueue[] sendRequestQueue;
    private final int maxPacketSize;
    private volatile PacketAssembler[] packetAssembler = new PacketAssembler[EncryptionLevel.values().length];


    public GlobalPacketAssembler(Version quicVersion, SendRequestQueue[] sendRequestQueues, GlobalAckGenerator globalAckGenerator, int maxPacketSize) {
        this.sendRequestQueue = sendRequestQueues;
        this.maxPacketSize = maxPacketSize;

        PacketNumberGenerator appSpacePnGenerator = new PacketNumberGenerator();

        Arrays.stream(EncryptionLevel.values()).forEach(level -> {
            int levelIndex = level.ordinal();
            AckGenerator ackGenerator =
                    (level != EncryptionLevel.ZeroRTT)?
                            globalAckGenerator.getAckGenerator(level.relatedPnSpace()):
                            // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-17.2.3
                            // "... a client cannot send an ACK frame in a 0-RTT packet, ..."
                            new NullAckGenerator();
            switch (level) {
                case ZeroRTT:
                case App:
                    packetAssembler[levelIndex] = new PacketAssembler(quicVersion, level, maxPacketSize, sendRequestQueue[levelIndex], ackGenerator, appSpacePnGenerator);
                    break;
                case Initial:
                    packetAssembler[levelIndex] = new InitialPacketAssembler(quicVersion, maxPacketSize, sendRequestQueue[levelIndex], ackGenerator);
                    break;
                default:
                    packetAssembler[levelIndex] = new PacketAssembler(quicVersion, level, maxPacketSize, sendRequestQueue[levelIndex], ackGenerator);
            }
        });
    }

    /**
     * Assembles packets for sending in one datagram. The total size of the QUIC packets returned will never exceed
     * max packet size and for packets not containing probes, it will not exceed the remaining congestion window size.
     * @param remainingCwndSize
     * @param sourceConnectionId
     * @param destinationConnectionId
     * @return
     */
    public List<SendItem> assemble(int remainingCwndSize, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        List<SendItem> packets = new ArrayList<>();
        int size = 0;
        boolean hasInitial = false;
        boolean hasPathChallengeOrResponse = false;

        int minPacketSize = 19 + destinationConnectionId.length;  // Computed for short header packet
        int remaining = Integer.min(remainingCwndSize, maxPacketSize);

        for (EncryptionLevel level: EncryptionLevel.values()) {
            PacketAssembler assembler = this.packetAssembler[level.ordinal()];
            if (assembler != null) {
                Optional<SendItem> item = assembler.assemble(remaining, maxPacketSize - size, sourceConnectionId, destinationConnectionId);
                if (item.isPresent()) {
                    packets.add(item.get());
                    int packetSize = item.get().getPacket().estimateLength();
                    size += packetSize;
                    remaining -= packetSize;
                    if (level == EncryptionLevel.Initial) {
                        hasInitial = true;
                    }
                    if (item.get().getPacket().getFrames().stream().anyMatch(f -> f instanceof PathChallengeFrame || f instanceof PathResponseFrame)) {
                        hasPathChallengeOrResponse = true;
                    }
                }
                if (remaining < minPacketSize && (maxPacketSize - size) < minPacketSize) {
                    // Trying a next level to produce a packet is useless
                    break;
                }
            }
        }

        if (hasInitial && size < 1200) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-14
            // "A client MUST expand the payload of all UDP datagrams carrying Initial packets to
            // at least 1200 bytes, by adding PADDING frames to the Initial packet or ..."
            int requiredPadding = 1200 - size;
            packets.stream()
                    .map(item -> item.getPacket())
                    .filter(p -> p instanceof InitialPacket)
                    .findFirst()
                    .ifPresent(initial -> initial.addFrame(new Padding(requiredPadding)));
            size += requiredPadding;
        }

        if (hasPathChallengeOrResponse && size < 1200) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-8.2.1
            // "An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to at least the smallest allowed
            //  maximum datagram size of 1200 bytes."
            // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-8.2.2
            // "An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame to at least the smallest allowed
            // maximum datagram size of 1200 bytes."
            int requiredPadding = 1200 - size;
            packets.stream()
                    .map(item -> item.getPacket())
                    .findFirst()
                    .ifPresent(packet -> packet.addFrame(new Padding(requiredPadding)));
            size += requiredPadding;
        }

        return packets;
    }

    public void stop(PnSpace pnSpace) {
        packetAssembler[pnSpace.relatedEncryptionLevel().ordinal()] = null;
    }

    public void setInitialToken(byte[] token) {
        ((InitialPacketAssembler) packetAssembler[EncryptionLevel.Initial.ordinal()]).setInitialToken(token);
    }
}

