/*
 * Copyright © 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic.stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

class BaseStreamTest {

    private BaseStream baseStream;

    @BeforeEach
    void initObjectUnderTest() {
        baseStream = new BaseStream();
    }

    @Test
    void availableReturnsZeroWhenNoBytesAvailable() {
        ByteBuffer buffer = ByteBuffer.allocate(50);
        long bytesAvailable = baseStream.bytesAvailable();

        assertThat(bytesAvailable).isEqualTo(0);
    }

    @Test
    void readDoesNotBlockWhenNoBytesAvailable() {
        ByteBuffer buffer = ByteBuffer.allocate(50);
        int read = baseStream.read(buffer);

        assertThat(read).isEqualTo(0);
    }

    @Test
    void missingStartShouldFailAllDataReceived() {
        baseStream = new BaseStream() {
            @Override
            protected boolean isStreamEnd(long offset) {
                return offset == 1000;
            }
        };

        baseStream.add(new SimpleStreamElement(100, 900));
        assertThat(baseStream.allDataReceived()).isFalse();

        baseStream.add(new SimpleStreamElement(0, 50));
        assertThat(baseStream.allDataReceived()).isFalse();

        baseStream.add(new SimpleStreamElement(50, 50));
        assertThat(baseStream.allDataReceived()).isTrue();
    }

    @Test
    void missingPartsShouldFailAllDataReceived() {
        baseStream = new BaseStream() {
            @Override
            protected boolean isStreamEnd(long offset) {
                return offset == 1000;
            }
        };

        baseStream.add(new SimpleStreamElement(0, 100));
        assertThat(baseStream.allDataReceived()).isFalse();

        baseStream.add(new SimpleStreamElement(800, 100));
        assertThat(baseStream.allDataReceived()).isFalse();

        baseStream.add(new SimpleStreamElement(400, 500));
        assertThat(baseStream.allDataReceived()).isFalse();

        baseStream.add(new SimpleStreamElement(900, 100));
        assertThat(baseStream.allDataReceived()).isFalse();

        baseStream.add(new SimpleStreamElement(100, 300));
        assertThat(baseStream.allDataReceived()).isTrue();
    }

    static class SimpleStreamElement implements StreamElement {

        private long offset;
        private int length;
        private byte[] data;

        public SimpleStreamElement(int offset, int length) {
            this.offset = offset;
            this.length = length;
            this.data = new byte[length];
        }

        @Override
        public long getOffset() {
            return offset;
        }

        @Override
        public int getLength() {
            return length;
        }

        @Override
        public byte[] getStreamData() {
            return data;
        }

        @Override
        public long getUpToOffset() {
            return offset + length;
        }

        @Override
        public int compareTo(StreamElement o) {
            return Long.compare(this.offset, o.getOffset());
        }
    }
}