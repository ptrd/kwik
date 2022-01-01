/*
 * Copyright © 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic.send;

import net.luminis.quic.*;
import net.luminis.quic.frame.Padding;
import net.luminis.quic.frame.PathChallengeFrame;
import net.luminis.quic.frame.PathResponseFrame;
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.ZeroRttPacket;

import java.time.Instant;
import java.util.*;

import static net.luminis.quic.EncryptionLevel.*;

/**
 * Assembles QUIC packets for sending.
 */
public class GlobalPacketAssembler {

    private SendRequestQueue[] sendRequestQueue;
    private volatile PacketAssembler[] packetAssembler = new PacketAssembler[EncryptionLevel.values().length];
    private volatile EncryptionLevel[] enabledLevels;


    public GlobalPacketAssembler(Version quicVersion, SendRequestQueue[] sendRequestQueues, GlobalAckGenerator globalAckGenerator) {
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
            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-14
            // "A client MUST expand the payload of all UDP datagrams carrying Initial packets to at least the smallest
            //  allowed maximum datagram size of 1200 bytes... "
            // "Similarly, a server MUST expand the payload of all UDP datagrams carrying ack-eliciting Initial packets
            //  to at least the smallest allowed maximum datagram size of 1200 bytes."
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
