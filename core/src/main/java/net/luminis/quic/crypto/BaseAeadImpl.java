/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.crypto;

import at.favre.lib.hkdf.HKDF;
import net.luminis.quic.impl.Role;
import net.luminis.quic.impl.Version;
import net.luminis.quic.log.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import static net.luminis.quic.impl.Role.Client;

public abstract class BaseAeadImpl implements Aead {

    public static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");

    // https://www.rfc-editor.org/rfc/rfc9001.html#name-packet-protection-keys
    // "The current encryption level secret and the label "quic key" are input to the KDF to produce the AEAD key; the
    //  label "quic iv" is used to derive the Initialization Vector (IV); see Section 5.3. The header protection key
    //  uses the "quic hp" label; see Section 5.4. Using these labels provides key separation between QUIC and TLS;
    //  see Section 9.6."
    public static final String QUIC_V1_KDF_LABEL_PREFIX = "quic ";

    // https://www.rfc-editor.org/rfc/rfc9369.html#name-hmac-based-key-derivation-f
    // "The labels used in [QUIC-TLS] to derive packet protection keys (Section 5.1), header protection keys (Section 5.4),
    //  Retry Integrity Tag keys (Section 5.8), and key updates (Section 6.1) change from "quic key" to "quicv2 key",
    //  from "quic iv" to "quicv2 iv", from "quic hp" to "quicv2 hp", and from "quic ku" to "quicv2 ku", to meet the
    //  guidance for new versions in Section 9.6 of that document."
    public static final String QUIC_V2_KDF_LABEL_PREFIX = "quicv2 ";

    private final Role nodeRole;
    private final Logger log;
    private final Version quicVersion;

    private byte[] trafficSecret;
    protected byte[] writeKey;
    protected byte[] writeIV;
    protected byte[] hp;
    protected Cipher hpCipher;
    protected SecretKeySpec writeKeySpec;
    protected Cipher writeCipher;

    public BaseAeadImpl(Version quicVersion, Role nodeRole, boolean initial, byte[] secret, byte[] hp, Logger log) {
        this.nodeRole = nodeRole;
        this.log = log;
        this.quicVersion = quicVersion;

        if (initial) {
            // https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2
            // "This produces an intermediate pseudorandom key (PRK) that is used to derive two separate secrets for
            //  sending and receiving. The secret used by clients to construct Initial packets uses the PRK and the
            //  label "client in" as input to the HKDF-Expand-Label function from TLS [TLS13] to produce a 32-byte secret.
            //  Packets constructed by the server use the same process with the label "server in". "
            byte[] initialNodeSecret = hkdfExpandLabel(quicVersion, secret, nodeRole == Client? "client in": "server in", "", (short) getHashLength());
            this.trafficSecret = initialNodeSecret;
            log.secret(nodeRole + " initial secret", initialNodeSecret);
            computeKeys(initialNodeSecret, true);
        }
        else {
            // https://www.rfc-editor.org/rfc/rfc9001.html#section-5.1
            // "Each encryption level has separate secret values for protection of packets sent in each direction. These
            //  traffic secrets are derived by TLS (see Section 7.1 of [TLS13]) and are used by QUIC for all encryption
            //  levels except the Initial encryption level. "
            //
            trafficSecret = secret;
            if (hp != null) {
                this.hp = hp;
                computeKeys(secret, false);
            }
            else {
                computeKeys(secret, true);
            }
        }
    }

    protected abstract short getKeyLength();

    protected abstract short getHashLength();

    protected abstract HKDF getHKDF();

    @Override
    public byte[] computeNextApplicationTrafficSecret() {
        // https://www.rfc-editor.org/rfc/rfc9001.html#section-6.1
        // "The endpoint creates a new write secret from the existing write secret as performed in Section 7.2 of [TLS13].
        //  This uses the KDF function provided by TLS with a label of "quic ku". The corresponding key and IV are created
        //  from that secret as defined in Section 5.1. The header protection key is not updated."
        // https://www.rfc-editor.org/rfc/rfc9369.html#section-3.3.2
        // "The labels used in [QUIC-TLS] to derive packet protection keys (Section 5.1), header protection keys (Section 5.4),
        //  Retry Integrity Tag keys (Section 5.8), and key updates (Section 6.1) change from "quic key" to "quicv2 key",
        //  from "quic iv" to "quicv2 iv", from "quic hp" to "quicv2 hp", and from "quic ku" to "quicv2 ku" "
        String prefix = quicVersion.isV2()? QUIC_V2_KDF_LABEL_PREFIX: QUIC_V1_KDF_LABEL_PREFIX;

        // https://datatracker.ietf.org/doc/html/rfc8446#section-7.2
        // "The next-generation application_traffic_secret is computed as:
        //  application_traffic_secret_N+1 = HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)"
        byte[] newApplicationTrafficSecret = hkdfExpandLabel(quicVersion, trafficSecret, prefix + "ku", "", (short) 32);
        log.secret("Computed updated (next) ApplicationTrafficSecret (" + nodeRole.toString().toLowerCase() + "): ", newApplicationTrafficSecret);
        return newApplicationTrafficSecret;
    }

    private void computeKeys(byte[] secret, boolean includeHP) {
        // https://www.rfc-editor.org/rfc/rfc9001.html#section-5.1
        // "The keys used for packet protection are computed from the TLS secrets using the KDF provided by TLS."
        // "The current encryption level secret and the label "quic key" are input to the KDF to produce the AEAD key;
        //  the label "quic iv" is used to derive the Initialization Vector (IV); see Section 5.3. The header protection
        //  key uses the "quic hp" label; "
        // "All uses of HKDF-Expand-Label in QUIC use a zero-length Context."
        String labelPrefix = quicVersion.isV2()? QUIC_V2_KDF_LABEL_PREFIX: QUIC_V1_KDF_LABEL_PREFIX;

        // https://tools.ietf.org/html/rfc8446#section-7.3
        byte[] key = hkdfExpandLabel(quicVersion, secret, labelPrefix + "key", "", getKeyLength());
        writeKey = key;
        writeKeySpec = null;
        log.secret(nodeRole + " key", key);

        byte[] iv = hkdfExpandLabel(quicVersion, secret, labelPrefix + "iv", "", (short) 12);
        writeIV = iv;
        log.secret(nodeRole + " iv", iv);

        if (includeHP) {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1
            // "The header protection key uses the "quic hp" label"
            hp = hkdfExpandLabel(quicVersion, encryptionLevelSecret, labelPrefix + "hp", "", getKeyLength());
            log.secret(nodeRole + " hp", hp);
        }
    }

    // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
    protected byte[] hkdfExpandLabel(Version quicVersion, byte[] secret, String label, String context, short length) {

        byte[] prefix = "tls13 ".getBytes(ISO_8859_1);

        ByteBuffer hkdfLabel = ByteBuffer.allocate(2 + 1 + prefix.length + label.getBytes(ISO_8859_1).length + 1 + context.getBytes(ISO_8859_1).length);
        hkdfLabel.putShort(length);
        hkdfLabel.put((byte) (prefix.length + label.getBytes().length));
        hkdfLabel.put(prefix);
        hkdfLabel.put(label.getBytes(ISO_8859_1));
        hkdfLabel.put((byte) (context.getBytes(ISO_8859_1).length));
        hkdfLabel.put(context.getBytes(ISO_8859_1));
        HKDF hkdf = getHKDF();
        return hkdf.expand(secret, hkdfLabel.array(), length);
    }

    @Override
    public byte[] getTrafficSecret() {
        return trafficSecret;
    }

    @Override
    public byte[] getWriteIV() {
        return writeIV;
    }

    @Override
    public byte[] getHp() {
        return hp;
    }

    public abstract Cipher getHeaderProtectionCipher();

    public abstract SecretKeySpec getWriteKeySpec();

    public abstract Cipher getWriteCipher();
}
