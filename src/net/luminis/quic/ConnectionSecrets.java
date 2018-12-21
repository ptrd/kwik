package net.luminis.quic;

import at.favre.lib.crypto.HKDF;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class ConnectionSecrets {

    private Logger log;

    enum NodeRole {
        Client,
        Server
    }

    // https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.2
    public static final byte[] STATIC_SALT = new byte[]{
            (byte) 0x9c, (byte) 0x10, (byte) 0x8f, (byte) 0x98,
            (byte) 0x52, (byte) 0x0a, (byte) 0x5c, (byte) 0x5c,
            (byte) 0x32, (byte) 0x96, (byte) 0x8e, (byte) 0x95,
            (byte) 0x0e, (byte) 0x8a, (byte) 0x2c, (byte) 0x5f,
            (byte) 0xe0, (byte) 0x6d, (byte) 0x6c, (byte) 0x38};

    NodeSecrets clientSecrets;
    NodeSecrets serverSecrets;
    NodeSecrets initialServerSecrets;
    NodeSecrets initialClientSecrets;

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

        clientSecrets = new NodeSecrets(initialSecret, NodeRole.Client, log);
        serverSecrets = new NodeSecrets(initialSecret, NodeRole.Server, log);
        initialClientSecrets = new NodeSecrets(initialSecret, NodeRole.Client, log);
        initialServerSecrets = new NodeSecrets(initialSecret, NodeRole.Server, log);
    }



}
