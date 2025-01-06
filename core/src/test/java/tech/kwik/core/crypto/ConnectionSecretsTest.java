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
package tech.kwik.core.crypto;

import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.ThrowableAssert.catchThrowable;
import static org.mockito.Mockito.mock;

class ConnectionSecretsTest {

    @Test
    void whenKeysAreNotSetExceptionCauseIsMissing() {
        // Given
        var connectionSecrets = new ConnectionSecrets(new VersionHolder(Version.getDefault()), Role.Client, null, mock(Logger.class));
        connectionSecrets.computeInitialKeys(new byte[8]);

        // When
        Throwable thrown = catchThrowable(() -> connectionSecrets.getPeerAead(EncryptionLevel.Handshake));

        // Then
        assertThat(thrown).isInstanceOf(MissingKeysException.class)
                        .hasMessageContaining("not installed");
        assertThat(((MissingKeysException) thrown).getMissingKeysCause()).isEqualTo(MissingKeysException.Cause.MissingKeys);
    }

    @Test
    void whenKeysAreSetButDiscardedExceptionCauseIsDiscarded() {
        // Given
        var connectionSecrets = new ConnectionSecrets(new VersionHolder(Version.getDefault()), Role.Client, null, mock(Logger.class));
        connectionSecrets.computeInitialKeys(new byte[8]);

        // When
        connectionSecrets.discardKeys(EncryptionLevel.Initial);
        Throwable thrown = catchThrowable(() -> connectionSecrets.getPeerAead(EncryptionLevel.Initial));

        // Then
        assertThat(thrown).isInstanceOf(MissingKeysException.class)
                        .hasMessageContaining("discarded");
        assertThat(((MissingKeysException) thrown).getMissingKeysCause()).isEqualTo(MissingKeysException.Cause.DiscardedKeys);
    }
}