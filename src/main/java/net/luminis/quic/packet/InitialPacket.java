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

import net.luminis.quic.frame.Padding;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.core.*;
import net.luminis.quic.generic.InvalidIntegerEncodingException;
import net.luminis.quic.generic.VariableLengthInteger;
import net.luminis.tls.util.ByteUtils;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

public class InitialPacket extends LongHeaderPacket {

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-initial-packet
    // "An Initial packet uses long headers with a type value of 0x00."
    private static int V1_type = 0;
    // https://www.rfc-editor.org/rfc/rfc9369.html#name-long-header-packet-types
    // "Initial: 0b01"
    private static int V2_type = 1;

    private byte[] token;

    public static boolean isInitial(ByteBuffer data) {
        data.mark();
        int flags = data.get();
        data.rewind();
        return (flags & 0xf0) == 0b1100_0000;
    }

    public static boolean isInitial(int type, Version quicVersion) {
        if (quicVersion.isV2()) {
            return type == V2_type;
        }
        else {
            return type == V1_type;
        }
    }

    public InitialPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, byte[] token, QuicFrame payload) {
        super(quicVersion, sourceConnectionId, destConnectionId, payload);
        this.token = token;
    }

    public InitialPacket(Version quicVersion) {
        super(quicVersion);
        token = null;
    }

    public InitialPacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, byte[] token, List<QuicFrame> frames) {
        super(quicVersion, sourceConnectionId, destConnectionId, frames);
        this.token = token;
    }

    public InitialPacket copy() {
        return new InitialPacket(quicVersion, sourceConnectionId, destinationConnectionId, token, frames);
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
        // Token length (variable-length integer)
        if (token != null) {
            VariableLengthInteger.encode(token.length, packetBuffer);
            packetBuffer.put(token);
        }
        else {
            packetBuffer.put((byte) 0x00);
        }
    }

    @Override
    protected int estimateAdditionalFieldsLength() {
        return token == null? 1: 1 + token.length;
    }

    @Override
    public EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.Initial;
    }

    @Override
    public PnSpace getPnSpace() {
        return PnSpace.Initial;
    }

    @Override
    public PacketProcessor.ProcessResult accept(PacketProcessor processor, Instant time, InetSocketAddress clientAddress) {
        return processor.process(this, time);
    }

    @Override
    protected void parseAdditionalFields(ByteBuffer buffer) throws InvalidPacketException {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.5:
        // "An Initial packet (shown in Figure 13) has two additional header
        // fields that are added to the Long Header before the Length field."
        try {
            long tokenLength = VariableLengthInteger.parseLong(buffer);
            if (tokenLength > 0) {
                if (tokenLength <= buffer.remaining()) {
                    token = new byte[(int) tokenLength];
                    buffer.get(token);
                }
                else {
                    throw new InvalidPacketException();
                }
            }
        } catch (InvalidIntegerEncodingException e) {
            throw new InvalidPacketException();
        }
    }

    public byte[] getToken() {
        return token;
    }

    @Override
    public String toString() {
        return "Packet "
                + (isProbe? "P": "")
                + getEncryptionLevel().name().charAt(0) + "|"
                + (packetNumber >= 0? packetNumber: ".") + "|"
                + "L" + "|"
                + (packetSize >= 0? packetSize: ".") + "|"
                + frames.size() + "  "
                + "Token=" + (token != null? ByteUtils.bytesToHex(token): "[]") + " "
                + frames.stream().map(f -> f.toString()).collect(Collectors.joining(" "));
    }

    public void ensureSize(int minimumSize) {
        int payloadSize = frames.stream().mapToInt(f -> f.getFrameLength()).sum();
        int estimatedPacketLength = 1 + 4 + 1
                + destinationConnectionId.length + sourceConnectionId.length + (token != null? token.length: 1)
                + 2 + 1 + payloadSize + 16;   // 16 is what encryption adds, note that final length might be larger due to multi-byte packet length
        int paddingSize = minimumSize - estimatedPacketLength;
        if (paddingSize > 0) {
            frames.add(new Padding(paddingSize));
        }
    }
}
