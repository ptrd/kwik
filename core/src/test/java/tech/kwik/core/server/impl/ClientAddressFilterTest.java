/*
 * Copyright © 2023, 2024, 2025 Peter Doornbosch
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.impl.TestUtils;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.DatagramFilter;
import tech.kwik.core.packet.InitialPacket;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.ShortHeaderPacket;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class ClientAddressFilterTest {

    private ClientAddressFilter filter;
    private DatagramFilter sink;
    private InetSocketAddress initialClientAddress;

    @BeforeEach
    void setup() {
        sink = mock(DatagramFilter.class);
        initialClientAddress = new InetSocketAddress("www.example.com", 45839);
        filter = new ClientAddressFilter(initialClientAddress, mock(Logger.class), sink);
    }

    @Test
    void filterAllowsPacketsFromInitialClientAddress() throws Exception {
        // When
        filter.processDatagram(createInitialPacket(), new PacketMetaData(Instant.now(), initialClientAddress, 0, 1207));

        // Then
        verify(sink).processDatagram(any(ByteBuffer.class), any(PacketMetaData.class));
    }

    @Test
    void filterDropsPacketsNotFromInitialClientAddress() throws Exception {
        // When
        InetSocketAddress otherAddress = new InetSocketAddress("www.example.com", 5840);
        filter.processDatagram(createInitialPacket(), new PacketMetaData(Instant.now(), otherAddress, 0, 1207));

        // Then
        verify(sink, never()).processDatagram(any(ByteBuffer.class), any(PacketMetaData.class));
    }

    @Test
    void filterShouldAllowShortHeaderPacketsFromDifferentAddress() throws Exception {
        // When
        InetSocketAddress otherAddress = new InetSocketAddress("www.example.com", 5840);
        filter.processDatagram(createShortHeaderPacket(), new PacketMetaData(Instant.now(), otherAddress, 0, 1207));

        // Then
        verify(sink).processDatagram(any(ByteBuffer.class), any(PacketMetaData.class));

    }

    ByteBuffer createInitialPacket() throws Exception {
        InitialPacket initialPacket = new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, List.of(new Padding(10)));
        initialPacket.setPacketNumber(1);
        Aead aead = TestUtils.createKeys();
        return ByteBuffer.wrap(initialPacket.generatePacketBytes(aead));
    }

    ByteBuffer createShortHeaderPacket() throws Exception {
        ShortHeaderPacket shortHeaderPacket = new ShortHeaderPacket(Version.getDefault(), new byte[]{ 0x0e, 0x0e, 0x0e, 0x0e }, new PingFrame());
        shortHeaderPacket.setPacketNumber(1);
        Aead aead = TestUtils.createKeys();
        return ByteBuffer.wrap(shortHeaderPacket.generatePacketBytes(aead));
    }
}