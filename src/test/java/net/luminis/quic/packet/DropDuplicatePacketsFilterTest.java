/*
 * Copyright © 2024 Peter Doornbosch
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
package net.luminis.quic.packet;

import net.luminis.quic.core.EncryptionLevel;
import net.luminis.quic.core.PnSpace;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.stream.Stream;

import static org.mockito.Mockito.*;


class DropDuplicatePacketsFilterTest {

    private DropDuplicatePacketsFilter filter;
    private PacketFilter endpoint;

    @BeforeEach
    void setUpObjectUnderTest() {
        endpoint = mock(PacketFilter.class);
        filter = new DropDuplicatePacketsFilter(endpoint, 10, 10, 10);
    }

    @Test
    void firstPacketOnInitialLevelWillBePassed() {
        // Given

        // When
        QuicPacket initialPacket = createInitialPacket(0);
        filter.processPacket(null, initialPacket);

        // Then
        verify(endpoint, times(1)).processPacket(any(), argThat(packet -> packet.getPacketNumber() == 0));
    }

    @Test
    void samePacketNumberOnDifferentLevelWillBePassed() {
        // Given
        QuicPacket initialPacket = createInitialPacket(0);
        filter.processPacket(null, initialPacket);
        clearInvocations(endpoint);

        // When
        QuicPacket handshakePacket = createHandshakePacket(0);
        filter.processPacket(null, handshakePacket);

        // Then
        verify(endpoint, times(1)).processPacket(any(), argThat(packet -> packet.getPacketNumber() == 0));
    }

    @Test
    void duplicatePacketWillBeDropped() {
        // Given
        QuicPacket packet3 = createInitialPacket(3);
        filter.processPacket(null, packet3);
        clearInvocations(endpoint);

        // When
        filter.processPacket(null, packet3);

        // Then
        verify(endpoint, never()).processPacket(any(), any(QuicPacket.class));
    }

    @Test
    void delayedPacketWillBeProcessed() {
        // Given
        createInitialPackets(0, 1, 2, 3, 5, 6, 7, 9).forEach(packet -> filter.processPacket(null, packet));
        clearInvocations(endpoint);

        // When
        filter.processPacket(null, createInitialPacket(4));

        // Then
        verify(endpoint, times(1)).processPacket(any(), argThat(packet -> packet.getPacketNumber() == 4));
    }

    @Test
    void delayedPacketInsideWindowWillBeProcessed() {
        // Given
        createInitialPackets(0, 1, 2, 3, 5, 6, 7, 9, 10, 11, 12, 13, 14).forEach(packet -> filter.processPacket(null, packet));
        // Window is now 5 .. 14
        clearInvocations(endpoint);

        // When
        filter.processPacket(null, createInitialPacket(8));

        // Then
        verify(endpoint, times(1)).processPacket(any(), argThat(packet -> packet.getPacketNumber() == 8));
    }

    @Test
    void afterTotalRollOverDelayedPacketInsideWindowWillBeProcessed() {
        // Given
        createInitialPackets(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23).forEach(packet -> filter.processPacket(null, packet));
        // Window is now 14 .. 23
        clearInvocations(endpoint);

        // When
        filter.processPacket(null, createInitialPacket(16));

        // Then
        verify(endpoint, times(1)).processPacket(any(), argThat(packet -> packet.getPacketNumber() == 16));
    }

    @Test
    void newPacketOutsideWindowsWillBeProcessed() {
        // Given
        createInitialPackets(0, 1, 2, 3, 5, 6, 7, 9, 10, 11).forEach(packet -> filter.processPacket(null, packet));
        clearInvocations(endpoint);

        // When
        filter.processPacket(null, createInitialPacket(12));

        // Then
        verify(endpoint, times(1)).processPacket(any(), argThat(packet -> packet.getPacketNumber() == 12));
    }

    @Test
    void duplicatePacketsInsideWindowWillBeDiscarded() {
        // Given
        createInitialPackets(0, 1, 2, 3, 5, 6, 7, 9, 10, 11).forEach(packet -> filter.processPacket(null, packet));
        // Window is now: 2 .. 11
        clearInvocations(endpoint);

        // When
        filter.processPacket(null, createInitialPacket(2));
        filter.processPacket(null, createInitialPacket(10));

        // Then
        verify(endpoint, never()).processPacket(any(), any(QuicPacket.class));
    }

    @Test
    void packetNumberOutsideWindowIsAlwaysDiscarded() {
        // Given
        createInitialPackets(0, 1, 2, 3, 5, 6, 7, 9, 10, 11, 14).forEach(packet -> filter.processPacket(null, packet));
        // Window is now: 5 .. 14
        clearInvocations(endpoint);

        // When
        filter.processPacket(null, createInitialPacket(0));
        filter.processPacket(null, createInitialPacket(1));
        filter.processPacket(null, createInitialPacket(2));
        filter.processPacket(null, createInitialPacket(3));
        filter.processPacket(null, createInitialPacket(4));

        // Then
        verify(endpoint, never()).processPacket(any(), any(QuicPacket.class));
    }

    @Test
    void duplicatePacketOutsideWindowIsDiscarded() {
        // Given
        createInitialPackets(0, 1, 2, 3, 5, 6, 7, 9, 10, 11).forEach(packet -> filter.processPacket(null, packet));
        // Window is now: 2 .. 11
        clearInvocations(endpoint);

        // When
        filter.processPacket(null, createInitialPacket(1));

        // Then
        verify(endpoint, never()).processPacket(any(), any(QuicPacket.class));
    }

    private QuicPacket createInitialPacket(int packetNumber) {
        QuicPacket packet = mock(QuicPacket.class);
        when(packet.getPacketNumber()).thenReturn((long) packetNumber);
        when(packet.getEncryptionLevel()).thenReturn(EncryptionLevel.Initial);
        when(packet.getPnSpace()).thenReturn(PnSpace.Initial);
        return packet;
    }

    private QuicPacket createHandshakePacket(int packetNumber) {
        QuicPacket packet = mock(QuicPacket.class);
        when(packet.getPacketNumber()).thenReturn((long) packetNumber);
        when(packet.getEncryptionLevel()).thenReturn(EncryptionLevel.Handshake);
        when(packet.getPnSpace()).thenReturn(PnSpace.Handshake);
        return packet;
    }

    private Stream<QuicPacket> createInitialPackets(Integer... packetNumbers) {
        return Stream.of(packetNumbers).map(this::createInitialPacket);
    }

    private Stream<QuicPacket> createHandshakePackets(Integer... packetNumbers) {
        return Stream.of(packetNumbers).map(this::createHandshakePacket);
    }
}