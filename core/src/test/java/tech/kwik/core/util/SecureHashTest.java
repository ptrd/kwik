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
package tech.kwik.core.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.test.ByteUtils;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;


class SecureHashTest {

    private SecureHash secureHash;

    @BeforeEach
    void setUp() {
        byte[] key = "1234567890123456".getBytes();
        secureHash = new SecureHash(key);
    }

    @Test
    void generatingHashForSameInputShouldReturnSameHash() {
        // Given
        byte[] input = ByteUtils.hexToBytes("cd8330cac6107e88");

        // When
        int hash1 = secureHash.generateHashCode(input);
        int hash2 = secureHash.generateHashCode(input);

        // Then
        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    void generatingHashForDifferentInputsShouldReturnDifferentHashes() {
        // Given
        byte[] input1 = ByteUtils.hexToBytes("cd8330cac6107e88");
        byte[] input2 = ByteUtils.hexToBytes("07e89cd8330cac61");
        // When
        int hash1 = secureHash.generateHashCode(input1);
        int hash2 = secureHash.generateHashCode(input2);

        // Then
        assertThat(hash1).isNotEqualTo(hash2);
    }

    @Test
    void generatingHashForSameInputButDifferentSeedsShouldReturnDifferentHash() {
        // Given
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        SecureHash secureHash2 = new SecureHash(key);

        byte[] input = ByteUtils.hexToBytes("cd8330cac6107e88");

        // When
        int hash1 = secureHash.generateHashCode(input);
        int hash2 = secureHash2.generateHashCode(input);

        // Then
        assertThat(hash1).isNotEqualTo(hash2);
    }
}