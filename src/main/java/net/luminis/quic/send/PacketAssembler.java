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
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.packet.HandshakePacket;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.packet.ShortHeaderPacket;

import java.util.function.Function;

/**
 * Assembles a quic packet, based on "send requests" that are previously queued.
 *
 */
public class PacketAssembler {

    private final Version quicVersion;
    EncryptionLevel level;
    int maxPacketSize;
    SendRequestQueue requestQueue;
    private final AckGenerator ackGenerator;


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
        if (ackGenerator.hasAckToSend()) {
            ackFrame = ackGenerator.generateAckForPacket(packetNumber);
        }
        QuicPacket packet = createPacket(sourceConnectionId, destinationConnectionId, ackFrame);
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
        if (packet.getFrames().size() > 0) {
            return packet;
        }
        else {
            return null;
        }
    }

    private QuicPacket createPacket(byte[] sourceConnectionId, byte[] destinationConnectionId, QuicFrame frame) {
        switch (level) {
            case Handshake:
                return new HandshakePacket(quicVersion, sourceConnectionId, destinationConnectionId, frame);
            case App:
                return new ShortHeaderPacket(quicVersion, destinationConnectionId, frame);
            default:
                return null;
        }

    }


}

