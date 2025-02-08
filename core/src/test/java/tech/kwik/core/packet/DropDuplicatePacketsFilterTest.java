/*
 * Copyright © 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.packet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.impl.TransportError;

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
    void firstPacketOnInitialLevelWillBePassed() throws Exception {
        // Given

        // When
        QuicPacket initialPacket = createInitialPacket(0);
        filter.processPacket(initialPacket, null);

        // Then
        verify(endpoint, times(1)).processPacket(argThat(packet -> packet.getPacketNumber() == 0), any());
    }

    @Test
    void samePacketNumberOnDifferentLevelWillBePassed() throws Exception {
        // Given
        QuicPacket initialPacket = createInitialPacket(0);
        filter.processPacket(initialPacket, null);
        clearInvocations(endpoint);

        // When
        QuicPacket handshakePacket = createHandshakePacket(0);
        filter.processPacket(handshakePacket, null);

        // Then
        verify(endpoint, times(1)).processPacket(argThat(packet -> packet.getPacketNumber() == 0), any());
    }

    @Test
    void duplicatePacketWillBeDropped() throws Exception {
        // Given
        QuicPacket packet3 = createInitialPacket(3);
        filter.processPacket(packet3, null);
        clearInvocations(endpoint);

        // When
        filter.processPacket(packet3, null);

        // Then
        verify(endpoint, never()).processPacket(any(QuicPacket.class), any());
    }

    @Test
    void delayedPacketWillBeProcessed() throws Exception {
        // Given
        createInitialPackets(0, 1, 2, 3, 5, 6, 7, 9).forEach(packet -> processPacket(filter, packet));
        clearInvocations(endpoint);

        // When
        filter.processPacket(createInitialPacket(4), null);

        // Then
        verify(endpoint, times(1)).processPacket(argThat(packet -> packet.getPacketNumber() == 4), any());
    }

    private void processPacket(PacketFilter filter, QuicPacket packet)  {
        try {
            filter.processPacket(packet, null);
        }
        catch (TransportError e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void delayedPacketInsideWindowWillBeProcessed() throws Exception {
        // Given
        createInitialPackets(0, 1, 2, 3, 5, 6, 7, 9, 10, 11, 12, 13, 14).forEach(packet -> processPacket(filter, packet));
        // Window is now 5 .. 14
        clearInvocations(endpoint);

        // When
        filter.processPacket(createInitialPacket(8), null);

        // Then
        verify(endpoint, times(1)).processPacket(argThat(packet -> packet.getPacketNumber() == 8), any());
    }

    @Test
    void afterTotalRollOverDelayedPacketInsideWindowWillBeProcessed() throws Exception {
        // Given
        createInitialPackets(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23).forEach(packet -> processPacket(filter, packet));
        // Window is now 14 .. 23
        clearInvocations(endpoint);

        // When
        filter.processPacket(createInitialPacket(16), null);

        // Then
        verify(endpoint, times(1)).processPacket(argThat(packet -> packet.getPacketNumber() == 16), any());
    }

    @Test
    void newPacketOutsideWindowsWillBeProcessed() throws Exception {
        // Given
        createInitialPackets(0, 1, 2, 3, 5, 6, 7, 9, 10, 11).forEach(packet -> processPacket(filter, packet));
        clearInvocations(endpoint);

        // When
        filter.processPacket(createInitialPacket(12), null);

        // Then
        verify(endpoint, times(1)).processPacket(argThat(packet -> packet.getPacketNumber() == 12), any());
    }

    @Test
    void duplicatePacketsInsideWindowWillBeDiscarded() throws Exception {
        // Given
        createInitialPackets(0, 1, 2, 3, 5, 6, 7, 9, 10, 11).forEach(packet -> processPacket(filter, packet));
        // Window is now: 2 .. 11
        clearInvocations(endpoint);

        // When
        filter.processPacket(createInitialPacket(2), null);
        filter.processPacket(createInitialPacket(10), null);

        // Then
        verify(endpoint, never()).processPacket(any(QuicPacket.class), any());
    }

    @Test
    void packetNumberOutsideWindowIsAlwaysDiscarded() throws Exception {
        // Given
        createInitialPackets(0, 1, 2, 3, 5, 6, 7, 9, 10, 11, 14).forEach(packet -> processPacket(filter, packet));
        // Window is now: 5 .. 14
        clearInvocations(endpoint);

        // When
        filter.processPacket(createInitialPacket(0), null);
        filter.processPacket(createInitialPacket(1), null);
        filter.processPacket(createInitialPacket(2), null);
        filter.processPacket(createInitialPacket(3), null);
        filter.processPacket(createInitialPacket(4), null);

        // Then
        verify(endpoint, never()).processPacket(any(QuicPacket.class), any());
    }

    @Test
    void duplicatePacketOutsideWindowIsDiscarded() throws Exception {
        // Given
        createInitialPackets(0, 1, 2, 3, 5, 6, 7, 9, 10, 11).forEach(packet -> processPacket(filter, packet));
        // Window is now: 2 .. 11
        clearInvocations(endpoint);

        // When
        filter.processPacket(createInitialPacket(1), null);

        // Then
        verify(endpoint, never()).processPacket(any(QuicPacket.class), any());
    }

    @Test
    void retryOrVersionNegotiationPacketsAreAlwaysProcessed() throws Exception {
        // Given
        QuicPacket packet = createNoPacketNumberPacket();

        // When
        filter.processPacket(packet, null);

        // Then
        verify(endpoint, times(1)).processPacket(eq(packet), any());
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

    private QuicPacket createNoPacketNumberPacket() {
        QuicPacket packet = mock(QuicPacket.class);
        when(packet.getPacketNumber()).thenReturn(null);
        when(packet.getEncryptionLevel()).thenReturn(null);
        when(packet.getPnSpace()).thenReturn(null);
        return packet;
    }
}