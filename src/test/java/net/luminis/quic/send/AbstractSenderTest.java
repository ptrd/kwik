/*
 * Copyright © 2020, 2021, 2022 Peter Doornbosch
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

import net.luminis.quic.AckGenerator;
import net.luminis.quic.EncryptionLevel;
import net.luminis.quic.Version;
import net.luminis.quic.crypto.Keys;
import net.luminis.quic.log.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.internal.util.reflection.FieldSetter;

import javax.crypto.Cipher;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AbstractSenderTest {

    public static final int MAX_PACKET_SIZE = 1232;

    protected Keys keys;
    protected Keys[] levelKeys = new Keys[4];

    @BeforeEach
    void initKeys() throws Exception {
        keys = createKeys();
        for (int i = 0; i < EncryptionLevel.values().length; i++) {
            levelKeys[i] = createKeys();
        }
    }

    protected Keys createKeys() throws Exception {
        Keys keys = mock(Keys.class);
        when(keys.getHp()).thenReturn(new byte[16]);
        when(keys.getWriteIV()).thenReturn(new byte[12]);
        when(keys.getWriteKey()).thenReturn(new byte[16]);
        Keys dummyKeys = new Keys(Version.getDefault(), new byte[16], null, mock(Logger.class));
        FieldSetter.setField(dummyKeys, Keys.class.getDeclaredField("hp"), new byte[16]);
        Cipher hpCipher = dummyKeys.getHeaderProtectionCipher();
        when(keys.getHeaderProtectionCipher()).thenReturn(hpCipher);
        FieldSetter.setField(dummyKeys, Keys.class.getDeclaredField("writeKey"), new byte[16]);
        Cipher wCipher = dummyKeys.getWriteCipher();
        // The Java implementation of this cipher (GCM), prevents re-use with the same iv.
        // As various tests often use the same packet numbers (used for creating the nonce), the cipher must be re-initialized for each test.
        // Still, a consequence is that generatePacketBytes cannot be called twice on the same packet.
        when(keys.getWriteCipher()).thenReturn(wCipher);
        when(keys.getWriteKeySpec()).thenReturn(dummyKeys.getWriteKeySpec());

        when(keys.aeadEncrypt(any(), any(), any())).thenCallRealMethod();
        when(keys.createHeaderProtectionMask(any())).thenCallRealMethod();

        return keys;
    }
}
