/*
 * Copyright © 2019 Peter Doornbosch
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
package net.luminis.quic;

import net.luminis.tls.ByteUtils;

import java.nio.ByteBuffer;
import java.util.stream.Collectors;

public class InitialPacket extends LongHeaderPacket {

    private final byte[] token;

    public InitialPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, byte[] token, int packetNumber, QuicFrame payload, ConnectionSecrets connectionSecrets) {
        super(quicVersion, sourceConnectionId, destConnectionId, packetNumber, payload);
        this.token = token;
        generateBinaryPacket(connectionSecrets);
    }

    public InitialPacket(Version quicVersion) {
        super(quicVersion);
        token = null;
    }

    protected byte getPacketType() {
        if (quicVersion.atLeast(Version.IETF_draft_17)) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.5
            // "|1|1| 0 |R R|P P|"
            // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.2
            // "The next two bits (those with a mask of 0x0c) of
            //      byte 0 are reserved.  These bits are protected using header
            //      protection (see Section 5.4 of [QUIC-TLS]).  The value included
            //      prior to protection MUST be set to 0."
            byte flags = (byte) 0xc0;  // 1100 0000
            return encodePacketNumberLength(flags, packetNumber);
        }
        else {
            return (byte) 0xff;
        }
    }

    protected void generateAdditionalFields() {
        // Token length (variable-length integer)
        if (token != null) {
            byte[] encodedTokenLength = QuicPacket.encodeVariableLengthInteger(token.length);
            packetBuffer.put(encodedTokenLength);
            packetBuffer.put(token);
        }
        else {
            packetBuffer.put((byte) 0x00);
        }
    }

    @Override
    protected EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.Initial;
    }

    @Override
    public void accept(PacketProcessor processor) {
        processor.process(this);
    }

    @Override
    protected void checkPacketType(byte type) {
        if (quicVersion.atLeast(Version.IETF_draft_17)) {
            byte masked = (byte) (type & 0xf0);
            if (masked != (byte) 0xc0) {
                // Programming error: this method shouldn't have been called if packet is not Initial
                throw new RuntimeException();
            }
        }
        else {
            if (type != (byte) 0xff) {
                // Programming error: this method shouldn't have been called if packet is not Initial
                throw new RuntimeException();
            }
        }
    }

    @Override
    protected void parseAdditionalFields(ByteBuffer buffer) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.5:
        // "An Initial packet (shown in Figure 13) has two additional header
        // fields that are added to the Long Header before the Length field."
        int tokenLength = buffer.get();
        if (tokenLength > 0) {
            buffer.position(buffer.position() + tokenLength);
        }
    }

    public byte[] getToken() {
        return token;
    }

    @Override
    public String toString() {
        return "Packet "
                + getEncryptionLevel().name().charAt(0) + "|"
                + packetNumber + "|"
                + "L" + "|"
                + packetSize + "|"
                + frames.size() + "  "
                + "Token=" + (token != null? ByteUtils.bytesToHex(token): "[]") + " "
                + frames.stream().map(f -> f.toString()).collect(Collectors.joining(" "));
    }
}
