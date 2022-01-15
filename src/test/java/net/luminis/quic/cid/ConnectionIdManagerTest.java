/*
 * Copyright © 2022 Peter Doornbosch
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
package net.luminis.quic.cid;

import net.luminis.quic.frame.NewConnectionIdFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.send.Sender;
import net.luminis.quic.server.ServerConnectionRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.function.Consumer;

import static net.luminis.quic.cid.ConnectionIdManager.MAX_CIDS_PER_CONNECTION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;


class ConnectionIdManagerTest {

    private ServerConnectionRegistry connectionRegistry;
    private Sender sender;
    private ConnectionIdManager connectionIdManager;

    @BeforeEach
    void initObjectUnderTest() {
        connectionRegistry = mock(ServerConnectionRegistry.class);
        sender = mock(Sender.class);
        connectionIdManager = new ConnectionIdManager(6, connectionRegistry, sender, mock(Logger.class));
    }

    @Test
    void whenConnectionCreatedNewConnectionIdsShouldBeSent() {
        // Given
        connectionIdManager.setPeerCidLimit(2);

        // When
        connectionIdManager.handshakeFinished();

        // Then
        verify(sender, atLeastOnce()).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }

    @Test
    void firstNewConnectionIdSentShouldHaveSequenceNumberOne() {
        // Given
        connectionIdManager.setPeerCidLimit(4);

        // When
        connectionIdManager.handshakeFinished();

        // Then
        ArgumentCaptor<QuicFrame> captor = ArgumentCaptor.forClass(QuicFrame.class);
        verify(sender, atLeastOnce()).send(captor.capture(), any(), any(Consumer.class));
        QuicFrame firstFrame = captor.getAllValues().get(0);
        assertThat(((NewConnectionIdFrame) firstFrame).getSequenceNr()).isEqualTo(1);
    }

    @Test
    void initialCidsShouldMatchPeerLimitMinusOne() {
        // Given
        connectionIdManager.setPeerCidLimit(4);

        // When
        connectionIdManager.handshakeFinished();

        // Then
        verify(sender, times(3)).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }

    @Test
    void whenPeerLimitIsLargeinitialCidsShouldMatchServerLimit() {
        // Given
        connectionIdManager.setPeerCidLimit(64);

        // When
        connectionIdManager.handshakeFinished();

        // Then
        verify(sender, times(MAX_CIDS_PER_CONNECTION - 1)).send(argThat(frame -> frame instanceof NewConnectionIdFrame), any(), any(Consumer.class));
    }
}