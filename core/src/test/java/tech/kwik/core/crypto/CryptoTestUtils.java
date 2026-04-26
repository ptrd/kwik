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
package tech.kwik.core.crypto;

import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.test.FieldSetter;

import javax.crypto.Cipher;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CryptoTestUtils {

    public static Aead createKeys() throws Exception {
        Aes128Gcm keys = mock(Aes128Gcm.class);
        when(keys.getHp()).thenReturn(new byte[16]);
        when(keys.getIv()).thenReturn(new byte[12]);
        Aes128Gcm dummyKeys = new Aes128Gcm(Version.getDefault(), Role.Client, true, new byte[16], null, mock(Logger.class));
        FieldSetter.setField(dummyKeys, BaseAeadImpl.class.getDeclaredField("hp"), new byte[16]);
        Cipher hpCipher = dummyKeys.getHeaderProtectionCipher();
        when(keys.getHeaderProtectionCipher()).thenReturn(hpCipher);
        FieldSetter.setField(dummyKeys, BaseAeadImpl.class.getDeclaredField("key"), new byte[16]);
        Cipher wCipher = dummyKeys.getCipher();
        // The Java implementation of this cipher (GCM), prevents re-use with the same iv.
        // As various tests often use the same packet numbers (used for creating the nonce), the cipher must be re-initialized for each test.
        // Still, a consequence is that generatePacketBytes cannot be called twice on the same packet.
        when(keys.getCipher()).thenReturn(wCipher);
        when(keys.getKeySpec()).thenReturn(dummyKeys.getKeySpec());

        when(keys.aeadEncrypt(any(), any(), any())).thenCallRealMethod();
        when(keys.aeadDecrypt(any(), any(), any())).thenCallRealMethod();
        when(keys.createHeaderProtectionMask(any())).thenCallRealMethod();

        return keys;
    }
}
