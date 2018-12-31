package net.luminis.quic;

import at.favre.lib.crypto.HKDF;
import net.luminis.tls.TlsState;

public class ConnectionSecrets {

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

    private Logger log;

    private NodeSecrets[] clientSecrets = new NodeSecrets[EncryptionLevel.values().length];
    private NodeSecrets[] serverSecrets = new NodeSecrets[EncryptionLevel.values().length];

    public ConnectionSecrets(Version quicVersion, Logger log) {
        this.log = log;
    }

    /**
     * Generate the initial secrets
     *
     * @param destConnectionId
     */
    public void computeInitialKeys(byte[] destConnectionId) {

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.2:
        // "The hash function for HKDF when deriving initial secrets and keys is SHA-256"
        HKDF hkdf = HKDF.fromHmacSha256();

        byte[] initialSecret = hkdf.extract(STATIC_SALT, destConnectionId);
        log.secret("Initial secret", initialSecret);

        clientSecrets[EncryptionLevel.Initial.ordinal()] = new NodeSecrets(initialSecret, NodeRole.Client, log);
        serverSecrets[EncryptionLevel.Initial.ordinal()] = new NodeSecrets(initialSecret, NodeRole.Server, log);
    }

    public void computeHandshakeSecrets(TlsState tlsState) {
        NodeSecrets handshakeSecrets = new NodeSecrets(NodeRole.Client, log);
        handshakeSecrets.computeHandshakeKeys(tlsState);
        clientSecrets[EncryptionLevel.Handshake.ordinal()] = handshakeSecrets;

        handshakeSecrets = new NodeSecrets(NodeRole.Server, log);
        handshakeSecrets.computeHandshakeKeys(tlsState);
        serverSecrets[EncryptionLevel.Handshake.ordinal()] = handshakeSecrets;
    }

    public void computeApplicationSecrets(TlsState tlsState) {
        NodeSecrets applicationSecrets = new NodeSecrets(NodeRole.Client, log);
        applicationSecrets.computeApplicationKeys(tlsState);
        clientSecrets[EncryptionLevel.App.ordinal()] = applicationSecrets;

        applicationSecrets = new NodeSecrets(NodeRole.Server, log);
        applicationSecrets.computeApplicationKeys(tlsState);
        serverSecrets[EncryptionLevel.App.ordinal()] = applicationSecrets;
    }

    public NodeSecrets getClientSecrets(EncryptionLevel encryptionLevel) {
        return clientSecrets[encryptionLevel.ordinal()];
    }

    public NodeSecrets getServerSecrets(EncryptionLevel encryptionLevel) {
        return serverSecrets[encryptionLevel.ordinal()];
    }
}
