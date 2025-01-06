/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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

import tech.kwik.core.impl.TestUtils;
import tech.kwik.core.impl.Version;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.frame.StreamFrame;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ShortHeaderPacketTest {

    @Test
    void packetWithMinimalFrameShouldBePaddedToGetEnoughBytesForEncrypting() throws Exception {
        ShortHeaderPacket shortHeaderPacket = new ShortHeaderPacket(Version.getDefault(), new byte[]{ 0x0e, 0x0e, 0x0e, 0x0e }, new PingFrame());
        shortHeaderPacket.setPacketNumber(1);

        Aead aead = TestUtils.createKeys();
        shortHeaderPacket.generatePacketBytes(aead);

        // If it gets here, it is already sure the encryption succeeded.
        assertThat(shortHeaderPacket.getFrames()).hasAtLeastOneElementOfType(PingFrame.class);
    }

    @Test
    void estimatedLengthShouldBeExactWhenPnIsKnown() throws Exception {
        byte[] destinationConnectionId = { 0x0e, 0x0b, 0x02, 0x0f, 0x0a, 0x04, 0x02, 0x0d };
        ShortHeaderPacket shortHeaderPacket = new ShortHeaderPacket(Version.getDefault(), destinationConnectionId, new StreamFrame(1, new byte[4], true));
        shortHeaderPacket.setPacketNumber(54321);

        int estimatedLength = shortHeaderPacket.estimateLength(0);
        int actualLength = shortHeaderPacket.generatePacketBytes(TestUtils.createKeys()).length;

        // Then
        assertThat(actualLength).isLessThanOrEqualTo(estimatedLength);  // By contract!
        assertThat(actualLength).isEqualTo(estimatedLength);            // In practice
    }

    @Test
    void whenPnUnknownEstimatedLengthShouldAssumeMaxPnLength() throws Exception {
        byte[] destinationConnectionId = { 0x0e, 0x0b, 0x02, 0x0f, 0x0a, 0x04, 0x02, 0x0d };
        ShortHeaderPacket shortHeaderPacket = new ShortHeaderPacket(Version.getDefault(), destinationConnectionId, new StreamFrame(1, new byte[4], true));

        int estimatedLength = shortHeaderPacket.estimateLength(0);

        shortHeaderPacket.setPacketNumber(0);
        int minLength = shortHeaderPacket.generatePacketBytes(TestUtils.createKeys()).length;

        // Then
        assertThat(minLength).isLessThanOrEqualTo(estimatedLength);       // By contract!
        assertThat(estimatedLength).isEqualTo(minLength + 3);    // In practice
    }

    @Test
    void estimatedLengthShouldNotBeLessThanActual() throws Exception {
        // Given (shortest possible payload and packet number -> not enough bytes for sample for header protection, so padding will be added when generating packet bytes)
        byte[] destinationConnectionId = { 0x0e, 0x0b, 0x02, 0x0f, 0x0a, 0x04, 0x02, 0x0d };
        ShortHeaderPacket shortHeaderPacket = new ShortHeaderPacket(Version.getDefault(), destinationConnectionId, new PingFrame());
        shortHeaderPacket.setPacketNumber(0);

        // When
        int estimatedLength = shortHeaderPacket.estimateLength(0);
        int actualLength = shortHeaderPacket.generatePacketBytes(TestUtils.createKeys()).length;

        // Then
        assertThat(actualLength).isLessThanOrEqualTo(estimatedLength);  // By contract!
        assertThat(actualLength).isEqualTo(estimatedLength);            // In practice
    }

}