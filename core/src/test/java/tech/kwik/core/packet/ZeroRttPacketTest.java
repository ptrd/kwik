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
package tech.kwik.core.packet;

import tech.kwik.core.impl.TestUtils;
import tech.kwik.core.impl.Version;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.frame.StreamFrame;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


class ZeroRttPacketTest {

    @Test
    void estimatedLengthWithToken() throws Exception {
        byte[] srcCid = new byte[4];
        byte[] destCid = new byte[8];
        QuicFrame payload = new StreamFrame(0, new byte[80], true);
        byte[] token = new byte[32];
        QuicPacket packet = new ZeroRttPacket(Version.getDefault(), srcCid, destCid, payload);
        packet.setPacketNumber(0);

        int estimatedLength = packet.estimateLength(0);

        int actualLength = packet.generatePacketBytes(TestUtils.createKeys()).length;

        assertThat(actualLength).isLessThanOrEqualTo(estimatedLength);  // By contract!
        assertThat(actualLength).isEqualTo(estimatedLength);            // In practice
    }
}