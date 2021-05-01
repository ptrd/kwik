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
package net.luminis.quic;

import net.luminis.quic.crypto.Keys;
import net.luminis.quic.log.Logger;
import net.luminis.tls.util.ByteUtils;
import org.mockito.internal.util.reflection.FieldSetter;

import javax.crypto.Cipher;

import static net.luminis.quic.Version.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TestUtils {

    /**
     * Create a valid Keys object that can be used for encrypting/decrypting packets in tests.
     * @return
     * @throws Exception
     */
    public static Keys createKeys() throws Exception {
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

    public static byte[] createValidInitial(Version quicVersion) {
        switch (quicVersion) {
            case IETF_draft_29:
                // ODCID: 67268378ae7dc13b   Packet length: 1200
                return ByteUtils.hexToBytes("cbff00001d0867268378ae7dc13b08d5aabb03c53eed7d0044966ba935ce8c9b5516c82781494d098f254ebecc3d2fc3c00b5f4a6f84ae435556be3b47443761a3ba8d454611fd4f8daa1206919c11a8c749cc1250c0d4642fa879f396fee00b9bb55faf81e712628348d6d99df13f3006a19bbc4a3100a4dc9ea0089bf9c9c50ede7d13c13d5c4cd0db4ba0b26c98ebb35beaf46950e7501db32db57f0f4b2c8e8905c8db9c884ad34e810221052ca4bad7385c11c6f99f6f7297b55b5ea032396c1207d97e66f2a11c6f4c0b8dcb6e7a337cb20a72893d3eadd571cf18a6dfc9985463ea26f02ab0d89b2401101bcfe334a00c13aafeb1ff5e78199ccec1e5e5fff747dff32227ae844abb6df9f6f383f8aa0fcfa6620212a53dc9693a9423ec1c8530773af6d403ebe650ed1c3496660be26acc4d7259f78db79e13c4aa8e886270d5da425fa8bbb4d6eecf6dbd95b7de021242b6194b6ad3659badc164284744c41e328681d632258bd8df0378f37ff1d8d98dc7523c185ed15bf1a18fe6e6e63e977a58c4a97ceb5ea4558f8f3242f0ef135300ca5e035c1576e164394ae8158114cd243db197e3471c4126006c80512d80052a1e5abefc89e4e67eeab86a684176ccc610c94b224c228c3cb38eba7890e4b983ed909352fba349dc0d994c4984a7c5acb0f34d6f872f18232f21f70f9d6328aa5a2db058b12b73a7fbee815235063db9960ab2ee65dd3924c6109d85eb825192a2ee16bb5c1fa14c0279d0b4d55a5414854a35a6003c94ff4e3a13b728df2a35b739e64ca070997db4319bcf414ae677e6a362177b3aae8bdebd652283b87ad2985cf0d20636561321c4e64e58eae9e723b02a880ce6d50ff180aca94c26fe092a5d94578c0283e90d7ad3901e25fa4e29fa88212eff3196e93bea9e8fc466a5cd58c8621fe303abffd669624d025787b674f38e80f07fb3cb6a27dcc2ee1ca2ba42944dcf3b9485e12bc3946bb3ac8a5a1765203e5949009cb04137b008dfc09f45f43b7bb21d96a0120600aa565ef074ae80b95e99dec947d948ce64066525906e5d2d9dceab57e4a76b4967c81399cabb28c3d119a7464e1e489c7e40a972ef4676155163924c85a1d52756f4b4018d218774e56e007d7e954675eb40ecad5745eeb8bc8c6dafa898dc6142d3997b5735418c2b9b81e1d70398ae0788d4a936775583b62ef777566f6e9ea71c6848e7aee12baf4c454fc3f57ffd2915aa0d9ea64d8d360ec86bcac5f8c8c5e793cad593d63d26283c32ea206ba3f4407865f0d0a6c7aa1d488b9ce0d32fd7d6469885422ccf228659b8ee566cda76520127b5395b6e7b911c8b0cdddc1d3e9dcaf08efdf1bf40c938b3f08d95d8974069575ddc3b81fef44de347b988cf6bdc33498192b70c2daf0c6ef43653ac96b7c95a2ffb3878985926ae19df2a6bfda342ce2622800fc1cce5a4b319bae73faa7455bd1a2b29df030b8bee6cac8d7a98cf20b6bb288604a0733a215a2bd395a781109cc0017bee36a2717f984ebaf09e9c788740a9fdab28cf66a7f84942c0ef49da17689697e7e6275577a2a22e9d0ba3e03bd56090f43a19493d6e997fc2678403174af27cbae35c113e6e74e583be8c34c03592fb61433ec573da50056ab707a86b293c9710394be5475d4bec3c087f8316b90151b894397d1475");
            case QUIC_version_1:
                return ByteUtils.hexToBytes("cc0000000112e03c1fe06e9141cfb854f6cb6249cdd5d4e21162f4a4a4d65784c78cd085828889385cb90044b79ff2be3251fc6b901291f50364c54e5b9da023e0ca517ac040db0f6539d3d24bd78d16b867b2f6002abd58ec30dd6c62527aa13f6c931b30be5d594469733b443311ba6fbc560fdde38b6968dbbdacc79b5b4f9b710e5aca0a670479fe29d1376becfb28740578a9ee4b7e82135042893f8f7872f377605b785ffca292f5a99074bdf0d95eacb25f4e897726ab495e72eff8b0cebf8c4fe0cbb2d303cfc97a716595b437a054820c032052fd7b17275e49684ce3b6572623a22f64087c33c65e306b5cadf3e268bc2ba19fa53aa836000f2f9cec92bf0c629fde7a00efc878f61e80efb1f1523aabb7ae430574ed484d284b3ad7a7e8c51ad18b53e3a50e2f5e95748e77c7a1c87aad27e1338ad07c5218695d5b877f4a5e05a52b1169038f80a41be4019668f8b3d735bb00bd9ce55c7e5f57743d5794bb9ed64462f8c31fece2b362ef7a22c8f0b3482378f8dbc0be8c078408b47bdfbeeb8dad7d1d14a348a71a7801faaf752d2ae55b66025ef71a12bcdb6ce61587251cce2fd62f4ede36cc8afeb34720d0abc06086a22cd30460098b7ba43f4a99b3b45a0720d37d3319cadd48055a30cbced0e1810e15ff4c27d1274423033e2f07b375ca1a02b2bb7f7baa7642052b62d8b435ac8ef1f1259257d0835db797c80f6eac7b11ce3b2bcb0a15673c74fac36a93b572b71e0abc1e95f0c911a68636738e4463472cabccc252978f46b914584e27e4ff438e42ecb41fbf06c733fe75ae0caf0203bf9141d1915da1e5491a07c59d4cff284370ddc68f29788f2f21f63d03fee614969d7c9ec8de0a4d30edc53ca027367e8b441569ea5b2e106d63ff7717739c2981af1e886c8411385da96383f00b780d0446b43835e0f856911d83081eeccc44dedc3ce2e043071892e485c68a01b4a02606b9238da7d6667c1960d28cb49ca0fe264ced99a90450ddbea009619d610960d7aada2c62f90fcc71d7bac6e6ae8cda184e6c0996de7efed7991f388350caa0ff6b0e5c06fa7b65dd9c7cef2af1e6b25b5f21c9a390fd09fbe1803f32546cca14961bc6f8bc6c9306d96eb3066fef7d7836b9dcc0c15175b04e207839bc0d9a2f3204629ab7ec5125d07920906fcdeea160db8b80ff55e4faffd09fbaa71820c8dd8a835730a5781bdfcb6cd9421a325db900c7d18d87c375495c0ee99efeebd4ad41c9c95176ca1965da2d355272f1b65bfc7004a46307198e261c9c0bc4151f8963a43d300017b5b01eb9265aa82bc753c9088635d120daa10d3458a0380559eea968577debc18f89df22eafa2b13d5b313bc74f8e23653241c8cd42eb73d5aa4be92adbd3ba541f4b80ed98a9a96bf6bb08ef145987927ff2dd491554ced7efb6ef1931fa00c7b16eb1a6519fc3518c0e9e09e8d0756145acfa058828e1ade21ad6067c03b8b236a0a876016b57f0beae846d47c649bfc70b7b38ab79730728e24785765b2c16755ed24391f8abc47acb7005f05256ab635cb86ae24226cea9e41837172de66ee0e327455a1ce404c2e04fbe04eb281310bc6a01586ea49de8bd86453f2d6a2b35c7012f16aab2c5f8d716d5bca22674cec644dddb291f07f6f3e19570c60d660cf8912833c46a27403b93ae4cbff6f5891a1103a5477782d311b6bcd0eff99fec82d03d40507ce11289757487a8a9ecda199d594c6253b8f1563c5c20586f70895");
            default:
                throw new IllegalStateException("Unexpected value: " + quicVersion);
        }
    }

    public static byte[] createInvalidInitial(Version quicVersion) {
        switch (quicVersion) {
            case IETF_draft_29:
                // ODCID: 67268378ae7dc13b   Packet length: 1200
                return ByteUtils.hexToBytes("cbff00001d0867268378ae7dc13b08d5aabb03c53eed7d0044966ba935ce00000000000000004d098f254ebecc3d2fc3c00b5f4a6f84ae435556be3b47443761a3ba8d454611fd4f8daa1206919c11a8c749cc1250c0d4642fa879f396fee00b9bb55faf81e712628348d6d99df13f3006a19bbc4a3100a4dc9ea0089bf9c9c50ede7d13c13d5c4cd0db4ba0b26c98ebb35beaf46950e7501db32db57f0f4b2c8e8905c8db9c884ad34e810221052ca4bad7385c11c6f99f6f7297b55b5ea032396c1207d97e66f2a11c6f4c0b8dcb6e7a337cb20a72893d3eadd571cf18a6dfc9985463ea26f02ab0d89b2401101bcfe334a00c13aafeb1ff5e78199ccec1e5e5fff747dff32227ae844abb6df9f6f383f8aa0fcfa6620212a53dc9693a9423ec1c8530773af6d403ebe650ed1c3496660be26acc4d7259f78db79e13c4aa8e886270d5da425fa8bbb4d6eecf6dbd95b7de021242b6194b6ad3659badc164284744c41e328681d632258bd8df0378f37ff1d8d98dc7523c185ed15bf1a18fe6e6e63e977a58c4a97ceb5ea4558f8f3242f0ef135300ca5e035c1576e164394ae8158114cd243db197e3471c4126006c80512d80052a1e5abefc89e4e67eeab86a684176ccc610c94b224c228c3cb38eba7890e4b983ed909352fba349dc0d994c4984a7c5acb0f34d6f872f18232f21f70f9d6328aa5a2db058b12b73a7fbee815235063db9960ab2ee65dd3924c6109d85eb825192a2ee16bb5c1fa14c0279d0b4d55a5414854a35a6003c94ff4e3a13b728df2a35b739e64ca070997db4319bcf414ae677e6a362177b3aae8bdebd652283b87ad2985cf0d20636561321c4e64e58eae9e723b02a880ce6d50ff180aca94c26fe092a5d94578c0283e90d7ad3901e25fa4e29fa88212eff3196e93bea9e8fc466a5cd58c8621fe303abffd669624d025787b674f38e80f07fb3cb6a27dcc2ee1ca2ba42944dcf3b9485e12bc3946bb3ac8a5a1765203e5949009cb04137b008dfc09f45f43b7bb21d96a0120600aa565ef074ae80b95e99dec947d948ce64066525906e5d2d9dceab57e4a76b4967c81399cabb28c3d119a7464e1e489c7e40a972ef4676155163924c85a1d52756f4b4018d218774e56e007d7e954675eb40ecad5745eeb8bc8c6dafa898dc6142d3997b5735418c2b9b81e1d70398ae0788d4a936775583b62ef777566f6e9ea71c6848e7aee12baf4c454fc3f57ffd2915aa0d9ea64d8d360ec86bcac5f8c8c5e793cad593d63d26283c32ea206ba3f4407865f0d0a6c7aa1d488b9ce0d32fd7d6469885422ccf228659b8ee566cda76520127b5395b6e7b911c8b0cdddc1d3e9dcaf08efdf1bf40c938b3f08d95d8974069575ddc3b81fef44de347b988cf6bdc33498192b70c2daf0c6ef43653ac96b7c95a2ffb3878985926ae19df2a6bfda342ce2622800fc1cce5a4b319bae73faa7455bd1a2b29df030b8bee6cac8d7a98cf20b6bb288604a0733a215a2bd395a781109cc0017bee36a2717f984ebaf09e9c788740a9fdab28cf66a7f84942c0ef49da17689697e7e6275577a2a22e9d0ba3e03bd56090f43a19493d6e997fc2678403174af27cbae35c113e6e74e583be8c34c03592fb61433ec573da50056ab707a86b293c9710394be5475d4bec3c087f8316b90151b894397d1475");
            default:
                throw new IllegalStateException("Unexpected value: " + quicVersion);
        }
    }
}

