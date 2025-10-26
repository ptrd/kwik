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
import tech.kwik.core.log.SysOutLogger;

import java.time.Duration;
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
        verify(serverConnection, never()).preTerminateHook();
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

    @Test
    void waitForAllConnectionsToCloseShouldTimeout() {
        // Given
        Duration timeout = Duration.ofMillis(25);
        registerConnectionWithOriginalAndInitialConnectionId(new byte[] {1, 2, 3}, new byte[] {4, 5, 6});

        // When
        long startTime = System.currentTimeMillis();
        serverConnectionRegistry.waitForAllConnectionsToClose(timeout);
        long elapsedTime = System.currentTimeMillis() - startTime;

        // Then
        assertThat(elapsedTime).isGreaterThanOrEqualTo(timeout.toMillis());
    }

    @Test
    void waitForAllConnectionsToCloseShouldReturnWhenAllConnectionsClosed() {
        // Given
        registerConnectionWithOriginalAndInitialConnectionId(new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 });

        // When
        new Thread(() -> {
            try {
                Thread.sleep(25); // Simulate some delay before closing the connection
                serverConnectionRegistry.deregisterConnectionId(new byte[] { 1, 2, 3 });
                serverConnectionRegistry.deregisterConnectionId(new byte[] { 4, 5, 6 });
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();

        Duration timeout = Duration.ofMillis(200);
        long startTime = System.currentTimeMillis();
        serverConnectionRegistry.waitForAllConnectionsToClose(timeout);
        long elapsedTime = System.currentTimeMillis() - startTime;

        // Then
        assertThat(serverConnectionRegistry.isEmpty()).isTrue();
        assertThat(elapsedTime)
                .isGreaterThanOrEqualTo(25)
                .isLessThan(2 * 25);
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