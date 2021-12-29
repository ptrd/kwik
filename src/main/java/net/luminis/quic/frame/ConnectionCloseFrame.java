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
package net.luminis.quic.frame;

import net.luminis.quic.InvalidIntegerEncodingException;
import net.luminis.quic.VariableLengthInteger;
import net.luminis.quic.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.packet.QuicPacket;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Represents a connection close frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames
 */
public class ConnectionCloseFrame extends QuicFrame {

    private long errorCode;
    private int triggeringFrameType;
    private byte[] reasonPhrase = new byte[0];
    private int tlsError = -1;
    private int frameType;

    /**
     * Creates a connection close frame for a normal connection close without errors
     * @param quicVersion
     */
    public ConnectionCloseFrame(Version quicVersion) {
        frameType = 0x1c;
        // https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-20
        // "NO_ERROR (0x0):  An endpoint uses this with CONNECTION_CLOSE to
        //      signal that the connection is being closed abruptly in the absence
        //      of any error."
        errorCode = 0x00;
    }

    public ConnectionCloseFrame(Version quicVersion, long error, String reason) {
        frameType = 0x1c;
        errorCode = error;
        if (errorCode >= 0x0100 && errorCode < 0x0200) {
            tlsError = (int) (errorCode - 256);
        }
        if (reason != null && !reason.isBlank()) {
            reasonPhrase = reason.getBytes(StandardCharsets.UTF_8);
        }
    }

    public ConnectionCloseFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        frameType = buffer.get() & 0xff;
        if (frameType != 0x1c && frameType != 0x1d) {
            throw new RuntimeException();  // Programming error
        }

        errorCode = VariableLengthInteger.parseLong(buffer);
        if (frameType == 0x1c) {
            triggeringFrameType = VariableLengthInteger.parse(buffer);
        }
        int reasonPhraseLength = VariableLengthInteger.parse(buffer);
        if (reasonPhraseLength > 0) {
            reasonPhrase = new byte[reasonPhraseLength];
            buffer.get(reasonPhrase);
        }

        if (frameType == 0x1c && errorCode >= 0x0100 && errorCode < 0x0200) {
            tlsError = (int) (errorCode - 256);
        }

        return this;
    }

    public boolean hasTransportError() {
        return frameType == 0x1c && errorCode != 0;
    }

    public boolean hasTlsError() {
        return tlsError != -1;
    }

    public long getTlsError() {
        if (hasTlsError()) {
            return tlsError;
        }
        else {
            throw new IllegalStateException("Close does not have a TLS error");
        }
    }

    public long getErrorCode() {
        return errorCode;
    }

    public boolean hasReasonPhrase() {
        return reasonPhrase != null;
    }

    public String getReasonPhrase() {
        try {
            return new String(reasonPhrase, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // Impossible: UTF-8 is always supported.
            return null;
        }
    }

    public boolean hasApplicationProtocolError() {
        return frameType == 0x1d && errorCode != 0;
    }

    public boolean hasError() {
        return hasTransportError() || hasApplicationProtocolError();
    }

    @Override
    public int getFrameLength() {
        return 1
                + VariableLengthInteger.bytesNeeded(errorCode)
                + VariableLengthInteger.bytesNeeded(0)
                + VariableLengthInteger.bytesNeeded(reasonPhrase.length)
                + reasonPhrase.length;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x1c);
        VariableLengthInteger.encode(errorCode, buffer);
        VariableLengthInteger.encode(0, buffer);
        VariableLengthInteger.encode(reasonPhrase.length, buffer);
        buffer.put(reasonPhrase);
    }

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-2
    // "All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered ack-eliciting."
    @Override
    public boolean isAckEliciting() {
        return false;
    }

    @Override
    public String toString() {
        return "ConnectionCloseFrame["
                + (hasTlsError()? "TLS " + tlsError: errorCode) + "|"
                + triggeringFrameType + "|"
                + (reasonPhrase != null? new String(reasonPhrase): "-") + "]";
    }

    @Override
    public void accept(FrameProcessor3 frameProcessor, QuicPacket packet, Instant timeReceived) {
        frameProcessor.process(this, packet, timeReceived);
    }
}
