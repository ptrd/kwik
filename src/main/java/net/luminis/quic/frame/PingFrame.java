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
package net.luminis.quic.frame;


import net.luminis.quic.Logger;
import net.luminis.quic.Version;

import java.nio.ByteBuffer;

public class PingFrame extends QuicFrame {

    public PingFrame(Version quicVersion) {
    }

    public PingFrame parse(ByteBuffer buffer, Logger log) {
        buffer.get();
        return this;
    }

    @Override
    public byte[] getBytes() {
        return new byte[] { 0x01 };
    }

    @Override
    public String toString() {
        return "PingFrame[]";
    }
}
