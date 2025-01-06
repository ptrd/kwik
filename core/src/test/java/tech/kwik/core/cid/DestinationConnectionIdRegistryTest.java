/*
 * Copyright © 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.cid;

import tech.kwik.core.log.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class DestinationConnectionIdRegistryTest {

    private DestinationConnectionIdRegistry connectionIdRegistry;

    @BeforeEach
    void initObjectUnderTest() {
        connectionIdRegistry = new DestinationConnectionIdRegistry(new byte[]{ 0x01, 0x10, 0x78, 0x33 }, mock(Logger.class));
        connectionIdRegistry.setInitialStatelessResetToken(new byte[]{ 0x01, 0x10, 0x78, 0x33 });
        connectionIdRegistry.registerNewConnectionId(1, new byte[] { 0x02, 0x1c, 0x56, 0x0b }, new byte[] { 0x02, 0x1c, 0x56, 0x0b });
        connectionIdRegistry.registerNewConnectionId(2, new byte[] { 0x03, 0x2a, 0x1f, 0x7e }, new byte[] { 0x03, 0x2a, 0x1f, 0x7e });
    }

    @Test
    void testUseNext() {
        byte[] newCid = connectionIdRegistry.useNext();
        assertThat(newCid).isEqualTo(new byte[] { 0x02, 0x1c, 0x56, 0x0b });
    }

    @Test
    void matchInitialStatelessResetToken() {
        assertThat(connectionIdRegistry.isStatelessResetToken(new byte[]{ 0x01, 0x10, 0x78, 0x33 })).isTrue();
    }

    @Test
    void matchNonInitialStatelessResetToken() {
        connectionIdRegistry.useNext();
        assertThat(connectionIdRegistry.isStatelessResetToken(new byte[]{ 0x02, 0x1c, 0x56, 0x0b })).isTrue();
    }

    @Test
    void matchingUnusedInitialStatelessResetTokenShouldFail() {
        assertThat(connectionIdRegistry.isStatelessResetToken(new byte[]{ 0x02, 0x1c, 0x56, 0x0b })).isFalse();
    }

    @Test
    void statelessResetTokenFromRetiredConnectionIdShouldNotBeMatched() {
        connectionIdRegistry.retireAllBefore(2);
        assertThat(connectionIdRegistry.isStatelessResetToken(new byte[] { 0x02, 0x1c, 0x56, 0x0b })).isFalse();
    }

    @Test
    void statelessResetTokenFromUsedConnectionIdShouldMatch() {
        connectionIdRegistry.useNext();
        connectionIdRegistry.useNext();
        assertThat(connectionIdRegistry.isStatelessResetToken(new byte[]{ 0x02, 0x1c, 0x56, 0x0b })).isTrue();
    }
}