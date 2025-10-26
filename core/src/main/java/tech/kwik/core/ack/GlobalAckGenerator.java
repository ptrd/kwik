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
package tech.kwik.core.ack;

import tech.kwik.core.common.PnSpace;
import tech.kwik.core.frame.AckFrame;
import tech.kwik.core.impl.FrameReceivedListener;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.recovery.RttProvider;
import tech.kwik.core.send.NullAckGenerator;
import tech.kwik.core.send.Sender;

import java.time.Instant;
import java.util.Arrays;

public class GlobalAckGenerator implements FrameReceivedListener<AckFrame> {

    private AckGenerator[] ackGenerators;

    public GlobalAckGenerator(Sender sender, RttProvider rttProvider) {
        ackGenerators = new AckGenerator[PnSpace.values().length];
        Arrays.stream(PnSpace.values()).forEach(pnSpace -> ackGenerators[pnSpace.ordinal()] = new AckGenerator(pnSpace, sender, rttProvider));
    }

    public void packetReceived(QuicPacket packet) {
        if (packet.canBeAcked()) {
            ackGenerators[packet.getPnSpace().ordinal()].packetReceived(packet);
        }
    }

    @Override
    public void received(AckFrame frame, PnSpace pnSpace, Instant timeReceived) {
        ackGenerators[pnSpace.ordinal()].process(frame);
    }

    public AckGenerator getAckGenerator(PnSpace pnSpace) {
        return ackGenerators[pnSpace.ordinal()];
    }

    public void discard(PnSpace pnSpace) {
        // Discard existing ackgenerator for given space, but install a no-op ack generator to catch calls for received
        // packets in that space. This is necessary because even the space is discarded, packets for that space might
        // be received and processed (until its keys are discarded).
        ackGenerators[pnSpace.ordinal()] = new NullAckGenerator();
    }
}
