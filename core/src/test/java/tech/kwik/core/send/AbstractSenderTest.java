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
package tech.kwik.core.send;

import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.impl.TestUtils;
import tech.kwik.core.crypto.Aead;
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
