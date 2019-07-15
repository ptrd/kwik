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

import java.nio.ByteBuffer;

public class ConnectionCloseFrame extends QuicFrame {

    private int errorCode;
    private int triggeringFrameType;
    private byte[] reasonPhrase;
    private int tlsError = -1;

    public ConnectionCloseFrame(Version quicVersion) {
    }

    public ConnectionCloseFrame parse(ByteBuffer buffer, Logger log) {
        int frameType = buffer.get() & 0xff;
        if (frameType != 0x1c && frameType != 0x1d) {
            throw new RuntimeException();  // Programming error
        }

        errorCode = VariableLengthInteger.parse(buffer);
        if (frameType == 0x1c) {
            triggeringFrameType = VariableLengthInteger.parse(buffer);
        }
        int reasonPhraseLength = VariableLengthInteger.parse(buffer);
        if (reasonPhraseLength > 0) {
            reasonPhrase = new byte[reasonPhraseLength];
            buffer.get(reasonPhrase);
        }
        else {
            reasonPhrase = new byte[0];
        }

        if (errorCode > 256) {
            tlsError = errorCode - 256;
        }

        // TODO: move to frame post processing
        log.error("Connection closed by peer with " + (tlsError >= 0? "TLS error " + tlsError: "error code " + errorCode) );
        return this;
    }

    @Override
    byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public String toString() {
        return "ConnectionCloseFrame[" + (tlsError >= 0? "TLS " + tlsError: errorCode) + "|" + triggeringFrameType + "|" + new String(reasonPhrase) + "]";
    }

}
