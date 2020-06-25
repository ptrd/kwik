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
import net.luminis.quic.packet.InitialPacket;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.packet.ShortHeaderPacket;

import java.util.List;
import java.util.function.Function;

/**
 * Assembles quic packets, based on "send requests" that are previously queued.
 *
 */
public class PacketAssembler {

    protected final Version quicVersion;
    protected final EncryptionLevel level;
    protected final int maxPacketSize;
    protected final SendRequestQueue requestQueue;
    protected final AckGenerator ackGenerator;


    public PacketAssembler(Version version, EncryptionLevel level, int maxPacketSize, SendRequestQueue requestQueue, AckGenerator ackGenerator) {
        quicVersion = version;
        this.level = level;
        this.maxPacketSize = maxPacketSize;
        this.requestQueue = requestQueue;
        this.ackGenerator = ackGenerator;
    }

    /**
     *
     * @param remainingCwndSize
     * @param packetNumber
     * @param sourceConnectionId        can be null when encryption level is 1-rtt; but not for the other levels; can be empty array though
     * @param destinationConnectionId
     * @return
     */
    QuicPacket assemble(int remainingCwndSize, long packetNumber, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        int remaining = Integer.min(remainingCwndSize, maxPacketSize);

        AckFrame ackFrame = null;
        // Check for an explicit ack, i.e. an ack on ack-eliciting packet that cannot be delayed (any longer)
        if (requestQueue.mustSendAck()) {
            ackFrame = ackGenerator.generateAckForPacket(packetNumber);
        }
        QuicPacket packet = createPacket(sourceConnectionId, destinationConnectionId, ackFrame);

        if (ackFrame == null && requestQueue.hasRequests()) {
            // If there is no explicit ack, but there is something to send, ack should always be included   // TODO: wrong, only if enough size
            if (ackGenerator.hasAckToSend()) {
                ackFrame = ackGenerator.generateAckForPacket(packetNumber);
                packet.addFrame(ackFrame);
            }
        }

        if (requestQueue.hasProbeWithData()) {
            // Probe is not limited by congestion control
            List<QuicFrame> probeData = requestQueue.getProbe();
            packet.addFrames(probeData);
            return packet;
        }

        int estimatedSize = packet.estimateLength();   // TODO: if larger than remaining, or even then remaining - x, abort.
        Function<Integer, QuicFrame> next;
        while ((next = requestQueue.next(remaining - estimatedSize)) != null) {
            QuicFrame nextFrame = next.apply(remaining - estimatedSize);
            if (nextFrame == null) {
                System.out.println("ERROR: supplier does not produce frame!");
            }
            else if (nextFrame.getBytes().length > remaining - estimatedSize) {
                System.out.println("ERROR: supplier does not produce frame of right (max) size: " + nextFrame.getBytes().length + " > " + (remaining - estimatedSize) + " frame: " + nextFrame);
            }
            estimatedSize += nextFrame.getBytes().length;
            packet.addFrame(nextFrame);
        }

        if (requestQueue.hasProbe() && packet.getFrames().isEmpty()) {
            requestQueue.getProbe();
            packet.addFrame(new PingFrame());
        }

        if (packet.getFrames().size() > 0) {
            return packet;
        }
        else {
            return null;
        }
    }

    protected QuicPacket createPacket(byte[] sourceConnectionId, byte[] destinationConnectionId, QuicFrame frame) {
        switch (level) {
            case Handshake:
                return new HandshakePacket(quicVersion, sourceConnectionId, destinationConnectionId, frame);
            case App:
                return new ShortHeaderPacket(quicVersion, destinationConnectionId, frame);
            default:
                throw new RuntimeException();  // programming error
        }

    }
}

