/*
 * Copyright © 2019, 2020 Peter Doornbosch
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
package net.luminis.quic.frame;

import net.luminis.quic.InvalidIntegerEncodingException;
import net.luminis.quic.VariableLengthInteger;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.time.Instant;

// https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-19.4
public class ApplicationCloseFrame extends QuicFrame {

    private int errorCode;
    private String reasonPhrase;

    public ApplicationCloseFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        if (buffer.get() != 0x03) {
            throw new RuntimeException();  // Would be a programming error.
        }

        errorCode = buffer.getShort() & 0xffff;
        int reasonPhraseLength = VariableLengthInteger.parse(buffer);
        if (reasonPhraseLength > 0) {
            byte[] data = new byte[reasonPhraseLength];
            buffer.get(data);
            reasonPhrase = new String(data);
        }
        else {
            reasonPhrase = "";
        }

        return this;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public String toString() {
        return "ApplicationCloseFrame[" + errorCode + "/" + reasonPhrase + "]";
    }

    @Override
    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}
