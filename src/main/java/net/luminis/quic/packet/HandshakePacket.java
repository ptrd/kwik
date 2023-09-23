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

import net.luminis.quic.core.EncryptionLevel;
import net.luminis.quic.core.PacketProcessor;
import net.luminis.quic.core.PnSpace;
import net.luminis.quic.core.Version;
import net.luminis.quic.frame.QuicFrame;

import java.nio.ByteBuffer;
import java.time.Instant;

public class HandshakePacket extends LongHeaderPacket {

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-handshake-packet
    // "A Handshake packet uses long headers with a type value of 0x02, ..."
    private static int V1_type = 2;
    // https://www.rfc-editor.org/rfc/rfc9369.html#name-long-header-packet-types
    // "Handshake: 0b11"
    private static int V2_type = 3;

    public static boolean isHandshake(int type, Version quicVersion) {
        if (quicVersion.isV2()) {
            return type == V2_type;
        }
        else {
            return type == V1_type;
        }
    }

    public HandshakePacket(Version quicVersion) {
        super(quicVersion);
    }

    public HandshakePacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, QuicFrame payload) {
        super(quicVersion, sourceConnectionId, destConnectionId, payload);
    }

    public HandshakePacket copy() {
        return new HandshakePacket(quicVersion, sourceConnectionId, destinationConnectionId, frames.size() > 0? frames.get(0): null);
    }

    @Override
    protected byte getPacketType() {
        if (quicVersion.isV2()) {
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
    public EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.Handshake;
    }

    @Override
    public PnSpace getPnSpace() {
        return PnSpace.Handshake;
    }

    @Override
    public PacketProcessor.ProcessResult accept(PacketProcessor processor, Instant time) {
        return processor.process(this, time);
    }

    @Override
    protected void parseAdditionalFields(ByteBuffer buffer) {
    }

}
