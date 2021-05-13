/*
 * Copyright © 2020, 2021 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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
package net.luminis.quic.packet;

import net.luminis.quic.TestUtils;
import net.luminis.quic.Version;
import net.luminis.quic.crypto.Keys;
import net.luminis.quic.frame.PingFrame;
import org.junit.jupiter.api.Test;


import static org.assertj.core.api.Assertions.assertThat;

class ShortHeaderPacketTest {

    @Test
    void packetWithMinimalFrameShouldBePaddedToGetEnoughBytesForEncrypting() throws Exception {
        ShortHeaderPacket shortHeaderPacket = new ShortHeaderPacket(Version.getDefault(), new byte[]{ 0x0e, 0x0e, 0x0e, 0x0e }, new PingFrame());

        Keys keys = TestUtils.createKeys();
        shortHeaderPacket.generatePacketBytes(1L, keys);

        // If it gets here, it is already sure the encryption succeeded.
        assertThat(shortHeaderPacket.getFrames()).hasAtLeastOneElementOfType(PingFrame.class);
    }

}