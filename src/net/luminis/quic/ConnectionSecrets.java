package net.luminis.quic;

import at.favre.lib.crypto.HKDF;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class ConnectionSecrets {

    private Logger log;

    // https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.2
    public static final byte[] STATIC_SALT = new byte[]{
            (byte) 0x9c, (byte) 0x10, (byte) 0x8f, (byte) 0x98,
            (byte) 0x52, (byte) 0x0a, (byte) 0x5c, (byte) 0x5c,
            (byte) 0x32, (byte) 0x96, (byte) 0x8e, (byte) 0x95,
            (byte) 0x0e, (byte) 0x8a, (byte) 0x2c, (byte) 0x5f,
            (byte) 0xe0, (byte) 0x6d, (byte) 0x6c, (byte) 0x38};

    public static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");
    byte[] clientWriteKey;
    byte[] clientWriteIV;
    byte[] clientPn;

    public ConnectionSecrets(Version quicVersion, Logger log) {
        this.log = log;
    }

    /**
     * Generate the initial secrets
     *
     * @param destConnectionId
     */
    public void generate(byte[] destConnectionId) {

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.2:
        // "The hash function for HKDF when deriving initial secrets and keys is SHA-256"
        HKDF hkdf = HKDF.fromHmacSha256();

        byte[] initialSecret = hkdf.extract(STATIC_SALT, destConnectionId);
        log.debug("Initial secret", initialSecret);

        // Client

        byte[] clientInitialSecret = hkdfExpandLabel(initialSecret, "client in", "", (short) 32);
        log.debug("Client initial secret", clientInitialSecret);

        // https://tools.ietf.org/html/rfc8446#section-7.3
        clientWriteKey = hkdfExpandLabel(clientInitialSecret, "key", "", (short) 16);
        log.debug("Client key", clientWriteKey);

        clientWriteIV = hkdfExpandLabel(clientInitialSecret, "iv", "", (short) 12);
        log.debug("Client iv", clientWriteIV);

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.1: 'to derive a packet number protection key (the "pn" label")'
        clientPn = hkdfExpandLabel(clientInitialSecret, "pn", "", (short) 16);
        log.debug("Client pn", clientPn);

        // Server

        byte[] serverInitialSecret = hkdfExpandLabel(initialSecret, "server in", "", (short) 32);
        log.debug("Server initial secret", clientInitialSecret);

        byte[] serverWriteKey = hkdfExpandLabel(serverInitialSecret, "key", "", (short) 16);
        log.debug("Server key", serverWriteKey);

        byte[] serverIV = hkdfExpandLabel(serverInitialSecret, "iv", "", (short) 12);
        log.debug("Server iv", clientWriteIV);

        byte[] serverPN = hkdfExpandLabel(serverInitialSecret, "pn", "", (short) 16);
        log.debug("Server pn", clientPn);
    }


    byte[] hkdfExpandLabel(byte[] secret, String label, String context, short length) {
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
