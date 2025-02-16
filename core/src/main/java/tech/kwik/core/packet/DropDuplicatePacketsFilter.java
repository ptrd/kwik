/*
 * Copyright © 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.packet;

import tech.kwik.core.common.PnSpace;
import tech.kwik.core.impl.TransportError;

import java.util.Arrays;

/**
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-numbers
 * "A receiver MUST discard a newly unprotected packet unless it is certain that it has not processed another packet
 *  with the same packet number from the same packet number space. Duplicate suppression MUST happen after removing
 *  packet protection for the reasons described in Section 9.5 of [QUIC-TLS]."
 *
 *  "Endpoints that track all individual packets for the purposes of detecting duplicates are at risk of accumulating
 *   excessive state. The data required for detecting duplicates can be limited by maintaining a minimum packet number
 *   below which all packets are immediately dropped. Any minimum needs to account for large variations in round-trip
 *   time, which includes the possibility that a peer might probe network paths with much larger round-trip times; ..."
 */
public class DropDuplicatePacketsFilter extends BasePacketFilter {

    final static int DEFAULT_WINDOW_SIZE_INITIAL = 32;
    final static int DEFAULT_WINDOW_SIZE_HANDSHAKE = 32;
    final static int DEFAULT_WINDOW_SIZE_APP = 1024;

    private final WindowBasedProcessedPacketChecker[] packetNumberSpace;

    public DropDuplicatePacketsFilter(PacketFilter next) {
        this(next, DEFAULT_WINDOW_SIZE_INITIAL, DEFAULT_WINDOW_SIZE_HANDSHAKE, DEFAULT_WINDOW_SIZE_APP);
    }

    public DropDuplicatePacketsFilter(PacketFilter next, int... windowSizes) {
        super(next);
        assert windowSizes.length == PnSpace.values().length;

        packetNumberSpace = new WindowBasedProcessedPacketChecker[PnSpace.values().length];
        for (PnSpace space: PnSpace.values()) {
            packetNumberSpace[space.ordinal()] = new WindowBasedProcessedPacketChecker(windowSizes[space.ordinal()]);
        }
    }

    @Override
    public void processPacket(QuicPacket packet, PacketMetaData metaData) throws TransportError {
        if (packet.getPnSpace() == null || packetNumberSpace[packet.getPnSpace().ordinal()].checkPacketNumber(packet)) {
            next(packet, metaData);
        }
        else {
            discard(packet, "duplicate packet");
        }
    }

    private class WindowBasedProcessedPacketChecker {

        private final int windowSize;
        private long[] processedPackets;

        public WindowBasedProcessedPacketChecker(int windowSize) {
            this.windowSize = windowSize;
            this.processedPackets = new long[windowSize];
            Arrays.fill(processedPackets, -1);
        }

        private boolean checkPacketNumber(QuicPacket packet) {
            Long packetNumber = packet.getPacketNumber();
            int index = (int) (packetNumber % windowSize);
            // packetNumber > processedPackets[index]  => packetNumber is certainly not yet processed
            // packetNumber == processedPackets[index] => packetNumber is certainly duplicate
            // packetNumber < processedPackets[index]  => outside window (packetNumber <= (processedPackets[index] - windowSize)),
            //                                            so packetNumber may be duplicate, but also may be not yet processed
            if (packetNumber > processedPackets[index]) {
                processedPackets[index] = packetNumber;
                return true;
            }
            else {
                return false;
            }
        }
    }
}
