/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.frame;


import tech.kwik.core.QuicConstants;
import tech.kwik.core.generic.IntegerTooLargeException;
import tech.kwik.core.generic.InvalidIntegerEncodingException;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.packet.QuicPacket;

import java.nio.ByteBuffer;
import java.time.Instant;

/**
 * Base class for all classes that represent a QUIC frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#frames
 */
public abstract class QuicFrame {

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-terms-and-definitions
    // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-2
    // "All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered ack-eliciting."

    /**
     * Returns whether the frame is ack eliciting
     * https://www.rfc-editor.org/rfc/rfc9000.html#name-terms-and-definitions
     * "Ack-eliciting packet: A QUIC packet that contains frames other than ACK, PADDING, and CONNECTION_CLOSE."
     * @return  true when the frame is ack-eliciting
     */
    public boolean isAckEliciting() {
        return true;
    }

    public abstract void accept(FrameProcessor frameProcessor, QuicPacket packet, Instant timeReceived);

    /**
     * Returns the length of the frame (in bytes) if it were to be serialized by the serialize method.
     * @return
     */
    public abstract int getFrameLength();

    public abstract void serialize(ByteBuffer buffer);

    /**
     * Parse a variable length integer from the buffer for which Kwik does not support a value larger than max int.
     * If the value is larger than Integer.MAX_VALUE, a TransportError of type INTERNAL_ERROR is thrown.
     * If the value itself is not correctly encoded, an InvalidIntegerEncodingException is thrown.
     * @param buffer
     * @return
     * @throws InvalidIntegerEncodingException
     * @throws TransportError
     */
    protected int parseVariableLengthIntegerLimitedToInt(ByteBuffer buffer) throws InvalidIntegerEncodingException, TransportError {
        try {
            return VariableLengthInteger.parseInt(buffer);
        }
        catch (IntegerTooLargeException e) {
            // This is not an invalid integer encoding, but a value that is too large for the implementation.
            throw new TransportError(QuicConstants.TransportErrorCode.INTERNAL_ERROR, "value too large");
        }
    }
}
