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
package net.luminis.quic.log;

import net.luminis.quic.log.BaseLogger;

import java.nio.ByteBuffer;

public class SysOutLogger extends BaseLogger {

    @Override
    protected void log(String message) {
        synchronized (this) {
            System.out.println(message);
        }
    }

    @Override
    protected void log(String message, Throwable error) {
        synchronized (this) {
            System.out.println(message);
            error.printStackTrace();
        }

    }

    @Override
    protected void logWithHexDump(String message, byte[] data, int length) {
        synchronized (this) {
            System.out.println(message);
            System.out.println(byteToHexBlock(data, length));
        }
    }

    @Override
    protected void logWithHexDump(String message, ByteBuffer data, int offset, int length) {
        synchronized (this) {
            System.out.println(message);
            System.out.println(byteToHexBlock(data, offset, length));
        }
    }

}
