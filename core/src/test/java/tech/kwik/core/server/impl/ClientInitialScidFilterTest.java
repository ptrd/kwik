/*
 * Copyright © 2025 Peter Doornbosch
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
package tech.kwik.core.server.impl;

import org.junit.jupiter.api.Test;
import tech.kwik.core.packet.DatagramFilter;
import tech.kwik.core.test.ByteUtils;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class ClientInitialScidFilterTest {

    @Test
    void filterShouldNotChangePositionInBuffer() throws Exception {
        byte[] originalSourceConnectionId = new byte[8];
        ClientInitialScidFilter filter = new ClientInitialScidFilter(originalSourceConnectionId, null, mock(DatagramFilter.class));
        byte[] data = ByteUtils.hexToBytes("ffaa6600c800000001080102030405060708080102030405060708");
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.position(4);

        filter.processDatagram(buffer, null);

        assertThat(buffer.position()).isEqualTo(4);
    }

    @Test
    void testExtractSourceConnectionId() throws Exception {
        byte[] originalSourceConnectionId = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        ClientInitialScidFilter filter = new ClientInitialScidFilter(originalSourceConnectionId, null, mock(DatagramFilter.class));
        byte[] data = ByteUtils.hexToBytes("c800000001070102030405060709010203040506070809");
        byte[] scid = filter.extractSourceConnectionId(ByteBuffer.wrap(data));

        assertThat(scid).isEqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 });
    }

    @Test
    void shortHeaderPacketShouldPassFilter() throws Exception {
        byte[] originalSourceConnectionId = new byte[8];
        DatagramFilter next = mock(DatagramFilter.class);
        ClientInitialScidFilter filter = new ClientInitialScidFilter(originalSourceConnectionId, null, next);
        byte[] data = ByteUtils.hexToBytes("41010203040506070801ffeeddccbbaa");
        ByteBuffer buffer = ByteBuffer.wrap(data);

        filter.processDatagram(buffer, null);

        verify(next).processDatagram(any(ByteBuffer.class), any());
    }

    @Test
    void version2InitialWithIncorrectScidShouldNotPassFilter() throws Exception {
        byte[] originalSourceConnectionId = new byte[8];
        DatagramFilter next = mock(DatagramFilter.class);
        ClientInitialScidFilter filter = new ClientInitialScidFilter(originalSourceConnectionId, null, next);
        byte[] data = ByteUtils.hexToBytes("d16b3343cf0801ff030405060708080102030405060708");
        ByteBuffer buffer = ByteBuffer.wrap(data);

        filter.processDatagram(buffer, null);

        verify(next, never()).processDatagram(any(ByteBuffer.class), any());
    }
}
