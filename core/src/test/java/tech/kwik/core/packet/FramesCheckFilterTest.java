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
package tech.kwik.core.packet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.frame.*;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class FramesCheckFilterTest {

    private BasePacketFilter next;
    private FramesCheckFilter filter;

    @BeforeEach
    void initObjectUnderTest() {
        next = mock(BasePacketFilter.class);
        when(next.logger()).thenReturn(mock(Logger.class));
        filter = new FramesCheckFilter(next, mock(Logger.class));
    }

    //region initial packet
    @Test
    void initialPacketWithoutFramesShouldBeDiscarded() throws Exception {
        // Given
        InitialPacket initialPacket = initialPacketWith();

        // When
        assertThatThrownBy(() ->
                filter.processPacket(initialPacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }

    @Test
    void initialPacketWithCryptoAndPaddingEtcShouldBeAccepted() throws Exception  {
        // Given
        InitialPacket initialPacket = initialPacketWith(
                new Padding(700),
                new PingFrame(),
                new AckFrame(0),
                new CryptoFrame(),
                new ConnectionCloseFrame(Version.getDefault())
        );

        // When
        filter.processPacket(initialPacket, null);

        // Then
        verify(next).processPacket(any(QuicPacket.class), any());
    }

    @Test
    void initialWithStreamFrameShouldBeDiscarded() throws TransportError {
        // Given
        InitialPacket initialPacket = initialPacketWith(new StreamFrame(0, new byte[0], false));

        // When
        assertThatThrownBy(() ->
                filter.processPacket(initialPacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }

    @Test
    void initialWithHandshakeDoneFrameShouldBeDiscarded() throws TransportError {
        // Given
        InitialPacket initialPacket = initialPacketWith(new HandshakeDoneFrame(Version.getDefault()));

        // When
        assertThatThrownBy(() ->
                filter.processPacket(initialPacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }

    @Test
    void initialWithConnectionCloseWithType1dShouldBeDiscarded() throws TransportError {
        // Given
        ConnectionCloseFrame ccFrame = new ConnectionCloseFrame(Version.getDefault(), 999, false, "app error");
        InitialPacket initialPacket = initialPacketWith(ccFrame);

        // When
        assertThatThrownBy(() ->
                filter.processPacket(initialPacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }
    //endregion

    //region handshake packet
    @Test
    void handshakePacketWithCryptoAndPaddingEtcShouldBeAccepted() throws Exception  {
        // Given
        HandshakePacket handshakePacket = handshakePacketWith(
                new Padding(700),
                new PingFrame(),
                new AckFrame(0),
                new CryptoFrame(),
                new ConnectionCloseFrame(Version.getDefault())
        );

        // When
        filter.processPacket(handshakePacket, null);

        // Then
        verify(next).processPacket(any(QuicPacket.class), any());
    }
    @Test
    void handshakeWithStreamFrameShouldBeDiscarded() throws TransportError {
        // Given
        HandshakePacket handshakePacket = handshakePacketWith(new StreamFrame(0, new byte[0], false));

        // When
        assertThatThrownBy(() ->
                filter.processPacket(handshakePacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }

    @Test
    void handshakeWithHandshakeDoneFrameShouldBeDiscarded() throws TransportError {
        // Given
        HandshakePacket handshakePacket = handshakePacketWith(new HandshakeDoneFrame(Version.getDefault()));

        // When
        assertThatThrownBy(() ->
                filter.processPacket(handshakePacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }

    @Test
    void handshakeWithConnectionCloseWithType1dShouldBeDiscarded() throws TransportError {
        // Given
        ConnectionCloseFrame ccFrame = new ConnectionCloseFrame(Version.getDefault(), 999, false, "app error");
        HandshakePacket handshakePacket = handshakePacketWith(ccFrame);

        // When
        assertThatThrownBy(() ->
                filter.processPacket(handshakePacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }

    //endregion

    //region 0-RTT packet
    @Test
    void zeroRttPacketWithoutFramesShouldBeDiscarded() throws Exception {
        // Given
        ZeroRttPacket zeroRttPacket = zeroRttPacketWith();

        // When
        assertThatThrownBy(() ->
                filter.processPacket(zeroRttPacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }

    @Test
    void zeroRttPacketWithCryptoFrameShouldBeDiscarded() throws Exception {
        // Given
        ZeroRttPacket zeroRttPacket = zeroRttPacketWith(new StreamFrame(0, new byte[48], false), new CryptoFrame());

        // When
        assertThatThrownBy(() ->
                filter.processPacket(zeroRttPacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }

    @Test
    void zeroRttPacketWithAckFrameShouldBeDiscarded() throws Exception {
        // Given
        ZeroRttPacket zeroRttPacket = zeroRttPacketWith(new StreamFrame(0, new byte[48], false), new AckFrame(0));

        // When
        assertThatThrownBy(() ->
                filter.processPacket(zeroRttPacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }

    @Test
    void zeroRttPacketWithNewTokenFrameShouldBeDiscarded() throws Exception {
        // Given
        ZeroRttPacket zeroRttPacket = zeroRttPacketWith(new NewTokenFrame(new byte[8]));

        // When
        assertThatThrownBy(() ->
                filter.processPacket(zeroRttPacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }

    @Test
    void zeroRttPacketWithPathResponseFrameShouldBeDiscarded() throws Exception {
        // Given
        ZeroRttPacket zeroRttPacket = zeroRttPacketWith(new PathResponseFrame(Version.getDefault(), new byte[8]));

        // When
        assertThatThrownBy(() ->
                filter.processPacket(zeroRttPacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }

    @Test
    void zeroRttPacketWithHandshakeDoneFrameShouldBeDiscarded() throws Exception {
        // Given
        ZeroRttPacket zeroRttPacket = zeroRttPacketWith(new HandshakeDoneFrame(Version.getDefault()));

        // When
        assertThatThrownBy(() ->
                filter.processPacket(zeroRttPacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }
    //endregion

    //region short header packet
    @Test
    void shortHeaderPacketWithoutFramesShouldBeDiscarded() throws Exception {
        // Given
        ShortHeaderPacket shortHeaderPacket = new ShortHeaderPacket(Version.getDefault());

        // When
        assertThatThrownBy(() ->
                filter.processPacket(shortHeaderPacket, null)
        ).isInstanceOf(TransportError.class);

        // Then
        verify(next, never()).next(any(QuicPacket.class), any());
    }
    //endregion

    //region retry packet
    @Test
    void retryPacketWithoutFramesShouldBeAccepted() throws Exception {
        // Given
        RetryPacket retryPacket = new RetryPacket(Version.getDefault(), new byte[8], new byte[8], new byte[8], new byte[8]);

        // When
        filter.processPacket(retryPacket, null);

        // Then
        verify(next).processPacket(any(QuicPacket.class), any());
    }
    //endregion

    //region version negotiation packet
    @Test
    void versionNegotiationPacketWithoutFramesShouldBeAccepted() throws Exception {
        // Given
        VersionNegotiationPacket versionNegotiationPacket = new VersionNegotiationPacket(Version.getDefault());

        // When
        filter.processPacket(versionNegotiationPacket, null);

        // Then
        verify(next).processPacket(any(QuicPacket.class), any());
    }

    //region test helper methods
    private static InitialPacket initialPacketWith(QuicFrame... frames) {
        return new InitialPacket(Version.getDefault(), new byte[8], new byte[8], null, List.of(frames));
    }

    private ZeroRttPacket zeroRttPacketWith(QuicFrame... frames) {
        return new ZeroRttPacket(Version.getDefault(), new byte[8], new byte[8], List.of(frames));
    }

    private HandshakePacket handshakePacketWith(QuicFrame... frames) {
        HandshakePacket handshakePacket = new HandshakePacket(Version.getDefault(), new byte[8], new byte[8], null);
        handshakePacket.addFrames(List.of(frames));
        return handshakePacket;
    }
    //endregion
}

