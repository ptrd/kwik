/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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

public class HandshakePacket extends LongHeaderPacket {

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
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.2
        // "|1|1|T T|R R|P P|"
        // "|  0x2 | Handshake       | Section 17.6 |"
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.2
        // "The next two bits (those with a mask of 0x0c) of
        //      byte 0 are reserved.  These bits are protected using header
        //      protection (see Section 5.4 of [QUIC-TLS]).  The value included
        //      prior to protection MUST be set to 0."
        byte flags = (byte) 0xe0;  // 1110 0000
        return encodePacketNumberLength(flags, packetNumber);
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
    protected void checkPacketType(byte type) {
        byte masked = (byte) (type & 0xf0);
        if (masked != (byte) 0xe0) {
            // Programming error: this method shouldn't have been called if packet is not Initial
            throw new RuntimeException();
        }
    }

    @Override
    protected void parseAdditionalFields(ByteBuffer buffer) {
    }

}
