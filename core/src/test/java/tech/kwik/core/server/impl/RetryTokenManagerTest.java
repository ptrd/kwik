/*
 * Copyright © 2026 Peter Doornbosch
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
import tech.kwik.core.test.TestClock;

import java.net.InetSocketAddress;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class RetryTokenManagerTest {

    private TestClock clock;
    private RetryTokenManager retryTokenManager;
    private InetSocketAddress clientAddress;
    private byte[] odcid;
    private byte[] retryScid;

    @BeforeEach
    void initObjectUnderTest() {
        clock = new TestClock();
        retryTokenManager = new RetryTokenManager(8, clock);
        clientAddress = new InetSocketAddress("127.0.0.1", 55333);
        odcid = new byte[] { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08 };
        retryScid = retryTokenManager.generateRetrySourceConnectionId();
    }

    //region token validation
    @Test
    void validTokenShouldReturnOriginalDestinationConnectionId() {
        // Given
        byte[] token = retryTokenManager.createToken(clientAddress, odcid, retryScid);

        // When / Then
        assertThat(retryTokenManager.validateToken(token, clientAddress, retryScid)).hasValue(odcid);
    }

    @Test
    void tokenWithEmptyOriginalDestinationConnectionIdShouldBeValid() {
        // Given
        byte[] token = retryTokenManager.createToken(clientAddress, new byte[0], retryScid);

        // When / Then
        assertThat(retryTokenManager.validateToken(token, clientAddress, retryScid)).hasValue(new byte[0]);
    }

    @Test
    void tokenSentFromDifferentPortShouldBeInvalid() {
        // Given
        byte[] token = retryTokenManager.createToken(clientAddress, odcid, retryScid);

        // When / Then
        assertThat(retryTokenManager.validateToken(token, new InetSocketAddress("127.0.0.1", 55334), retryScid)).isEmpty();
    }

    @Test
    void tokenSentFromDifferentAddressShouldBeInvalid() {
        // Given
        byte[] token = retryTokenManager.createToken(clientAddress, odcid, retryScid);

        // When / Then
        assertThat(retryTokenManager.validateToken(token, new InetSocketAddress("127.0.0.2", 55333), retryScid)).isEmpty();
    }

    @Test
    void tokenSentToDifferentConnectionIdShouldBeInvalid() {
        // Given
        byte[] token = retryTokenManager.createToken(clientAddress, odcid, retryScid);

        // When / Then
        assertThat(retryTokenManager.validateToken(token, clientAddress, odcid)).isEmpty();
    }

    @Test
    void modifiedTokenShouldBeInvalid() {
        // Given
        byte[] token = retryTokenManager.createToken(clientAddress, odcid, retryScid);
        token[20] ^= 0x01;

        // When / Then
        assertThat(retryTokenManager.validateToken(token, clientAddress, retryScid)).isEmpty();
    }

    @Test
    void truncatedTokenShouldBeInvalid() {
        // Given
        byte[] token = retryTokenManager.createToken(clientAddress, odcid, retryScid);

        // When / Then
        assertThat(retryTokenManager.validateToken(Arrays.copyOf(token, token.length - 1), clientAddress, retryScid)).isEmpty();
        assertThat(retryTokenManager.validateToken(new byte[3], clientAddress, retryScid)).isEmpty();
        assertThat(retryTokenManager.validateToken(null, clientAddress, retryScid)).isEmpty();
    }

    @Test
    void tokenCreatedByOtherServerInstanceShouldBeInvalid() {
        // Given
        byte[] token = new RetryTokenManager(8, clock).createToken(clientAddress, odcid, retryScid);

        // When / Then
        assertThat(retryTokenManager.validateToken(token, clientAddress, retryScid)).isEmpty();
    }
    //endregion

    //region token expiry
    @Test
    void tokenShouldBeValidJustBeforeExpiry() {
        // Given
        byte[] token = retryTokenManager.createToken(clientAddress, odcid, retryScid);

        // When
        clock.fastForward((int) RetryTokenManager.TOKEN_VALIDITY.toMillis() - 1);

        // Then
        assertThat(retryTokenManager.validateToken(token, clientAddress, retryScid)).hasValue(odcid);
    }

    @Test
    void expiredTokenShouldBeInvalid() {
        // Given
        byte[] token = retryTokenManager.createToken(clientAddress, odcid, retryScid);

        // When
        clock.fastForward((int) RetryTokenManager.TOKEN_VALIDITY.toMillis() + 1);

        // Then
        assertThat(retryTokenManager.validateToken(token, clientAddress, retryScid)).isEmpty();
    }
    //endregion

    //region connection id
    @Test
    void retrySourceConnectionIdShouldHaveConfiguredLength() {
        assertThat(new RetryTokenManager(12, clock).generateRetrySourceConnectionId()).hasSize(12);
    }
    //endregion
}
