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
package tech.kwik.core.log;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;


public class FileLogger extends BaseLogger {

    private File logFile;
    private PrintStream logStream;

    public FileLogger(File logFile) throws IOException {
        this.logFile = logFile;
        logStream = new PrintStream(new BufferedOutputStream(new FileOutputStream(logFile)));
    }

    @Override
    protected void log(String message) {
        synchronized (this) {
            logStream.println(message);
            logStream.flush();
        }
    }

    @Override
    protected void log(String message, Throwable ex) {
        synchronized (this) {
            logStream.println(message);
            ex.printStackTrace(logStream);
            logStream.flush();
        }
    }

    @Override
    protected void logWithHexDump(String message, byte[] data, int length) {
        synchronized (this) {
            logStream.println(message);
            logStream.println(byteToHexBlock(data, length));
            logStream.flush();
        }

    }

    @Override
    protected void logWithHexDump(String message, ByteBuffer data, int offset, int length) {
        synchronized (this) {
            logStream.println(message);
            logStream.println(byteToHexBlock(data, offset, length));
            logStream.flush();
        }
    }
}
