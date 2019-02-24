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

public abstract class QuicFrame {

    abstract byte[] getBytes();

    byte[] encodeVariableLengthInteger(long value) {
        if (value <= 63)
            return new byte[] { (byte) value };
        else if (value <= 16383) {
            ByteBuffer buffer = ByteBuffer.allocate(2);
            buffer.putShort((short) value);
            byte[] bytes = buffer.array();
            bytes[0] = (byte) (bytes[0] | (byte) 0x40);
            return bytes;
        }
        else {
            // TODO
            throw new RuntimeException("NIY");
        }
    }

    public boolean isAckEliciting() {
        return true;
    }
}
