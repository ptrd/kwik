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
import net.luminis.quic.packet.InitialPacket;

import java.util.*;

public class GlobalPacketAssembler {

    private SendRequestQueue[] sendRequestQueue;
    private final int maxPacketSize;
    private volatile PacketAssembler[] packetAssembler = new PacketAssembler[EncryptionLevel.values().length];


    public GlobalPacketAssembler(Version quicVersion, SendRequestQueue[] sendRequestQueues, GlobalAckGenerator globalAckGenerator, int maxPacketSize) {
        this.sendRequestQueue = sendRequestQueues;
        this.maxPacketSize = maxPacketSize;

        Arrays.stream(EncryptionLevel.values()).forEach(level -> {
            int levelIndex = level.ordinal();
            AckGenerator ackGenerator = globalAckGenerator.getAckGenerator(level.relatedPnSpace());
            packetAssembler[levelIndex] =
                    (level == EncryptionLevel.Initial)?
                            new InitialPacketAssembler(quicVersion, maxPacketSize, sendRequestQueue[levelIndex], ackGenerator):
                            new PacketAssembler(quicVersion, level, maxPacketSize, sendRequestQueue[levelIndex], ackGenerator);
        });
    }


    public List<SendItem> assemble(int remainingCwndSize, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        List<SendItem> packets = new ArrayList<>();
        int size = 0;
        boolean hasInitial = false;

        int minPacketSize = 19 + destinationConnectionId.length;  // Computed for short header packet
        int remaining = Integer.min(remainingCwndSize, maxPacketSize);

        for (EncryptionLevel level: EncryptionLevel.values()) {
            if (packetAssembler[level.ordinal()] != null) {
                Optional<SendItem> item = packetAssembler[level.ordinal()].assemble(remaining, sourceConnectionId, destinationConnectionId);
                if (item.isPresent()) {
                    packets.add(item.get());
                    int packetSize = item.get().getPacket().estimateLength();
                    size += packetSize;
                    remaining -= packetSize;
                    if (level == EncryptionLevel.Initial) {
                        hasInitial = true;
                    }
                }
                if (size + minPacketSize >= remainingCwndSize) {
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

