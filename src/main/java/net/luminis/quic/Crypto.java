package net.luminis.quic;

import at.favre.lib.crypto.HKDF;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class Crypto {

    public static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");

     static byte[] hkdfExpandLabel(byte[] secret, String label, String context, short length) {
        // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
        ByteBuffer hkdfLabel = ByteBuffer.allocate(2 + 1 + 5 + label.getBytes(ISO_8859_1).length + 1 + context.getBytes(ISO_8859_1).length);
        hkdfLabel.putShort(length);
        hkdfLabel.put((byte) (5 + label.getBytes().length));
        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.1: 'the label for HKDF-Expand-Label uses the prefix "quic " rather than "tls13 "'
        hkdfLabel.put("quic ".getBytes(ISO_8859_1));
        hkdfLabel.put(label.getBytes(ISO_8859_1));
        hkdfLabel.put((byte) (context.getBytes(ISO_8859_1).length));
        hkdfLabel.put(context.getBytes(ISO_8859_1));
        HKDF hkdf = HKDF.fromHmacSha256();
        return hkdf.expand(secret, hkdfLabel.array(), length);
    }
}
