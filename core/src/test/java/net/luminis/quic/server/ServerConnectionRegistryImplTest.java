/*
 * Copyright © 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.server;

import net.luminis.quic.log.SysOutLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.*;

class ServerConnectionRegistryImplTest {

    private ServerConnectionRegistryImpl serverConnectionRegistry;

    @BeforeEach
    void initObjectUnderTest() {
        serverConnectionRegistry = new ServerConnectionRegistryImpl(new SysOutLogger());
    }

    @Test
    void removeConnectionShouldRemoveBothOriginalDcidAndActiveCid() {
        // Given
        byte[] originalDcid = new byte[] {1, 2, 3};
        byte[] connectionId = new byte[] {4, 5, 6};

        registerConnectionWithOriginalAndInitialConnectionId(originalDcid, connectionId);

        // When
        ServerConnectionImpl serverConnection = mock(ServerConnectionImpl.class);
        when(serverConnection.getOriginalDestinationConnectionId()).thenReturn(originalDcid);
        when(serverConnection.getActiveConnectionIds()).thenReturn(List.of(connectionId));
        serverConnectionRegistry.removeConnection(serverConnection);

        // Then
        assertThat(serverConnectionRegistry.isEmpty()).isTrue();
    }

    @Test
    void removedConnectionShouldNotBeTerminatedAgain() {
        // Given
        byte[] originalDcid = new byte[] {1, 2, 3};
        byte[] connectionId = new byte[] {4, 5, 6};

        registerConnectionWithOriginalAndInitialConnectionId(originalDcid, connectionId);

        // When
        ServerConnectionImpl serverConnection = mock(ServerConnectionImpl.class);
        when(serverConnection.getOriginalDestinationConnectionId()).thenReturn(originalDcid);
        when(serverConnection.getActiveConnectionIds()).thenReturn(List.of(connectionId));
        serverConnectionRegistry.removeConnection(serverConnection);

        // Then
        verify(serverConnection, never()).terminate();
    }

    @Test
    void ifAnActiveConnectionIdNotPresentRemoveMethodRemovesAllAnyway() {
        // Given
        byte[] originalDcid = new byte[] {1, 2, 3};
        byte[] connectionId = new byte[] {4, 5, 6};

        registerConnectionWithOriginalAndInitialConnectionId(originalDcid, connectionId);

        // When
        ServerConnectionImpl serverConnection = mock(ServerConnectionImpl.class);
        when(serverConnection.getOriginalDestinationConnectionId()).thenReturn(originalDcid);
        when(serverConnection.getActiveConnectionIds()).thenReturn(List.of(new byte[] {4, 5, 6}, new byte[] {7, 8, 9}));
        serverConnectionRegistry.removeConnection(serverConnection);

        // Then
        assertThat(serverConnectionRegistry.isEmpty()).isTrue();
    }

    @Test
    void ifNoActiveCidPresentRemoveMethodDoesNotThrow() {
        // Given
        byte[] originalDcid = new byte[] {1, 2, 3};
        byte[] connectionId = new byte[] {4, 5, 6};

        registerConnectionWithOriginalAndInitialConnectionId(originalDcid, connectionId);

        // When
        ServerConnectionImpl serverConnection = mock(ServerConnectionImpl.class);
        when(serverConnection.getOriginalDestinationConnectionId()).thenReturn(originalDcid);
        when(serverConnection.getActiveConnectionIds()).thenReturn(List.of(new byte[] {7, 8, 9}));

        // Then
        assertThatCode(() -> {
            serverConnectionRegistry.removeConnection(serverConnection);
        }).doesNotThrowAnyException();
    }

    void registerConnectionWithOriginalAndInitialConnectionId(byte[] originalDcid, byte[] connectionId) {
        ServerConnectionCandidate serverConnectionCandidate = mock(ServerConnectionCandidate.class);
        when(serverConnectionCandidate.getOriginalDestinationConnectionId()).thenReturn(originalDcid);
        serverConnectionRegistry.registerConnection(serverConnectionCandidate, originalDcid);

        ServerConnectionProxy serverConnectionProxy = mock(ServerConnectionProxy.class);
        when(serverConnectionProxy.getOriginalDestinationConnectionId()).thenReturn(originalDcid);
        serverConnectionRegistry.registerConnection(serverConnectionProxy, connectionId);
    }
}