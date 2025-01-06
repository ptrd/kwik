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
package tech.kwik.h09.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Input stream (filter) that reads a limited number of bytes from the underlying stream. If caller tries to
 * read beyond the maximum, an exception is thrown.
 */
public class LimitedInputStream extends FilterInputStream {

    private final long limit;
    private long bytesRead;

    public LimitedInputStream(InputStream in, long limit) {
        super(in);
        this.limit = limit;
    }

    @Override
    public int read() throws IOException {
        if (bytesRead < limit) {
            int read = super.read();
            bytesRead++;
            return read;
        }
        else {
            throw new LimitExceededException(limit);
        }

    }

    @Override
    public int read(byte[] b) throws IOException {
        return super.read(b, 0, b.length);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (bytesRead < limit) {
            int read = super.read(b, off, (int) Long.min(limit - bytesRead, len));
            bytesRead += read;
            return read;
        }
        else {
            throw new LimitExceededException(limit);
        }
    }
}
