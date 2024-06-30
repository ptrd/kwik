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
package net.luminis.quic.crypto;

import net.luminis.quic.impl.Role;
import net.luminis.quic.impl.Version;
import net.luminis.quic.log.Logger;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class ChaCha20Test {

    @Test
    void whenPossibleKeyUpdateInProgressNewWriteKeyShouldBeUsed() {
        // Given
        ChaCha20 chaCha20 = new ChaCha20(Version.getDefault(), Role.Client, mock(Logger.class));
        chaCha20.computeKeys(new byte[32]);
        SecretKeySpec originalWriteKeySpec = chaCha20.getWriteKeySpec();

        // When
        chaCha20.checkKeyPhase((short) 1);

        // Then
        assertThat(chaCha20.getWriteKeySpec()).isNotSameAs(originalWriteKeySpec);
    }
}