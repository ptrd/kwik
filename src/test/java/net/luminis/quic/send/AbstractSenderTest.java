/*
 * Copyright © 2020, 2021, 2022, 2023 Peter Doornbosch
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
package net.luminis.quic.send;

import net.luminis.quic.crypto.Aead;
import net.luminis.quic.core.EncryptionLevel;
import net.luminis.quic.core.TestUtils;
import org.junit.jupiter.api.BeforeEach;

public class AbstractSenderTest {

    public static final int MAX_PACKET_SIZE = 1232;

    protected Aead aead;
    protected Aead[] levelKeys = new Aead[4];

    @BeforeEach
    void initKeys() throws Exception {
        aead = TestUtils.createKeys();
        for (int i = 0; i < EncryptionLevel.values().length; i++) {
            levelKeys[i] = TestUtils.createKeys();
        }
    }
}
