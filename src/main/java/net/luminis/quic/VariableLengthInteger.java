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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;


// https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-16
public class VariableLengthInteger {

    public static int parse(ByteBuffer buffer) {
        int value;
        byte firstLengthByte = buffer.get();
        switch ((firstLengthByte & 0xc0) >> 6) {
            case 0:
                value = firstLengthByte;
                break;
            case 1:
                value = ((firstLengthByte & 0x3f) << 8) | (buffer.get() & 0xff);
                break;
            case 2:
                value = ((firstLengthByte & 0x3f) << 24) | ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
                break;
            case 3:
                // TODO -> long
                throw new NotYetImplementedException();
            default:
                // Impossible, just to satisfy the compiler
                throw new RuntimeException();
        }
        return value;
    }

    public static int parse(InputStream inputStream) throws IOException {
        int value;
        int firstLengthByte = inputStream.read();
        if (firstLengthByte == -1) {
            throw new EOFException();
        }
        switch ((firstLengthByte & 0xc0) >> 6) {
            case 0:
                value = firstLengthByte;
                break;
            case 1:
                int nextByte = inputStream.read();
                if (nextByte == -1) {
                    throw new EOFException();
                }
                value = ((firstLengthByte & 0x3f) << 8) | (nextByte & 0xff);
                break;
            case 2:
                int byte2 = inputStream.read();
                int byte3 = inputStream.read();
                int byte4 = inputStream.read();
                if (byte2 == -1 || byte3 == -1 || byte4 == -1) {
                    throw new EOFException();
                }
                value = ((firstLengthByte & 0x3f) << 24) | ((byte2 & 0xff) << 16) | ((byte3 & 0xff) << 8) | (byte4 & 0xff);
                break;
            case 3:
                // TODO -> long
                throw new NotYetImplementedException();
            default:
                // Impossible, just to satisfy the compiler
                throw new RuntimeException();
        }
        return value;
    }

    public static int encode(int value, ByteBuffer buffer) {
        if (value <= 63) {
            buffer.put((byte) value);
            return 1;
        }
        else if (value <= 16383) {
            buffer.put((byte) ((value / 256) | 0x40));
            buffer.put((byte) (value % 256));
            return 2;
        }
        else if (value <= 1073741823) {
            int initialPosition = buffer.position();
            buffer.putInt(value);
            buffer.put(initialPosition, (byte) (buffer.get(initialPosition) | (byte) 0x80));
            return 4;
        }
        else {
            int initialPosition = buffer.position();
            buffer.putLong(value);
            buffer.put(initialPosition, (byte) (buffer.get(initialPosition) | (byte) 0xc0));
            return 8;
        }
    }


}
