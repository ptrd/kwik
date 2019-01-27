/*
 * Copyright © 2019 Peter Doornbosch
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

import at.favre.lib.crypto.HKDF;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class Crypto {

    public static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");

    // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
    static byte[] hkdfExpandLabel(Version quicVersion, byte[] secret, String label, String context, short length) {

        byte[] prefix;
        if (quicVersion.atLeast(Version.IETF_draft_17)) {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1:
            // "The keys used for packet protection are computed from the TLS secrets using the KDF provided by TLS."
            prefix = "tls13 ".getBytes(ISO_8859_1);
        }
        else {
            // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.1: 'the label for HKDF-Expand-Label uses the prefix "quic " rather than "tls13 "'
            prefix = "quic ".getBytes(ISO_8859_1);
        }

        ByteBuffer hkdfLabel = ByteBuffer.allocate(2 + 1 + prefix.length + label.getBytes(ISO_8859_1).length + 1 + context.getBytes(ISO_8859_1).length);
        hkdfLabel.putShort(length);
        hkdfLabel.put((byte) (prefix.length + label.getBytes().length));
        hkdfLabel.put(prefix);
        hkdfLabel.put(label.getBytes(ISO_8859_1));
        hkdfLabel.put((byte) (context.getBytes(ISO_8859_1).length));
        hkdfLabel.put(context.getBytes(ISO_8859_1));
        HKDF hkdf = HKDF.fromHmacSha256();
        return hkdf.expand(secret, hkdfLabel.array(), length);
    }
}
