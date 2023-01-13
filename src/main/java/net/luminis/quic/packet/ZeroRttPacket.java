/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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
package net.luminis.quic.packet;

import net.luminis.quic.EncryptionLevel;
import net.luminis.quic.PacketProcessor;
import net.luminis.quic.PnSpace;
import net.luminis.quic.Version;
import net.luminis.quic.frame.QuicFrame;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

public class ZeroRttPacket extends LongHeaderPacket {

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-0-rtt
    // "A 0-RTT packet uses long headers with a type value of 0x01."
    private static int V1_type = 1;
    // https://www.ietf.org/archive/id/draft-ietf-quic-v2-01.html#name-long-header-packet-types
    // "0-RTT packets use a packet type field of 0b10"
    private static int V2_type = 2;


    public static boolean isZeroRTT(int type, Version quicVersion) {
        if (quicVersion.isV2()) {
            return type == V2_type;
        }
        else {
            return type == V1_type;
        }
    }

    public ZeroRttPacket(Version quicVersion) {
        super(quicVersion);
    }

    public ZeroRttPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, QuicFrame frame) {
        super(quicVersion, sourceConnectionId, destConnectionId, frame);
    }

    public ZeroRttPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, List<QuicFrame> frames) {
        super(quicVersion, sourceConnectionId, destConnectionId, frames);
    }

    @Override
    protected byte getPacketType() {
        if (quicVersion.isV2()) {
            // https://www.ietf.org/archive/id/draft-ietf-quic-v2-01.html#name-long-header-packet-types
            // "0-RTT packets use a packet type field of 0b10"
            return (byte) V2_type;
        }
        else {
            return (byte) V1_type;
        }
    }

    @Override
    protected void generateAdditionalFields(ByteBuffer packetBuffer) {
    }

    @Override
    protected int estimateAdditionalFieldsLength() {
        return 0;
    }

    @Override
    protected void parseAdditionalFields(ByteBuffer buffer) {
    }

    @Override
    public EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.ZeroRTT;
    }

    @Override
    public PnSpace getPnSpace() {
        return PnSpace.App;
    }

    @Override
    public PacketProcessor.ProcessResult accept(PacketProcessor processor, Instant time) {
         return processor.process(this, time);
    }

    @Override
    public String toString() {
        return "Packet "
                + getEncryptionLevel().name().charAt(0) + "|"
                + (packetNumber >= 0? packetNumber: ".") + "|"
                + "Z" + "|"
                + (packetSize >= 0? packetSize: ".") + "|"
                + frames.size() + "  "
                + frames.stream().map(f -> f.toString()).collect(Collectors.joining(" "));
    }

}
