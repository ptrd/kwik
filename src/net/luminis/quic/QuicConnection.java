package net.luminis.quic;

import net.luminis.tls.KeyShareExtension;
import net.luminis.tls.TlsState;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

import static net.luminis.quic.EncryptionLevel.Handshake;
import static net.luminis.quic.EncryptionLevel.Initial;
import static net.luminis.tls.Tls13.generateKeys;

/**
 * Creates and maintains a QUIC connection with a QUIC server.
 */
public class QuicConnection {

    private Logger log;
    private final Version quicVersion;
    private final Random random = new Random();
    private final String host;
    private final int port;
    private byte[] sourceConnectionId;
    private byte[] destConnectionId;
    private ConnectionSecrets connectionSecrets;
    private List<CryptoStream> cryptoStreams = new ArrayList<>();
    private TlsState tlsState;
    private DatagramSocket socket;
    private final InetAddress serverAddress;
    private int[] lastPacketNumber = new int[EncryptionLevel.values().length];


    public QuicConnection(String host, int port, Version quicVersion) throws UnknownHostException {
        log = new Logger();
        log.debug("Creating connection with " + host + ":" + port + " with " + quicVersion);
        this.host = host;
        this.port = port;
        serverAddress = InetAddress.getByName(host);
        this.quicVersion = quicVersion;
    }

    /**
     * Set up the connection with the server.
     */
    public void connect() throws IOException {
        generateConnectionIds(8, 8);
        generateInitialKeys();

        // Create client hello
        ECKey[] keys = new ECKey[0];
        try {
            keys = generateKeys("secp256r1");
        } catch (Exception e) {
            throw new RuntimeException();
        }
        ECPrivateKey privateKey = (ECPrivateKey) keys[0];
        ECPublicKey publicKey = (ECPublicKey) keys[1];

        byte[] clientHello = createClientHello(host, publicKey);
        tlsState = new QuicTlsState();
        tlsState.clientHelloSend(privateKey, clientHello);

        // Wrap it in a long header packet
        LongHeaderPacket longHeaderPacket = new InitialPacket(quicVersion, sourceConnectionId, destConnectionId, lastPacketNumber[Initial.ordinal()]++, new CryptoFrame(clientHello), connectionSecrets);
        log.debugWithHexBlock("Sending packet", longHeaderPacket.getBytes());

        socket = new DatagramSocket();
        send(longHeaderPacket, "client hello");

        socket.setSoTimeout(5000);
        byte[] receiveBuffer = new byte[1500];
        DatagramPacket receivedPacket;
        for (int i = 0; i < 3; i++) {
            receivedPacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
            socket.receive(receivedPacket);
            log.debugWithHexBlock("Received packet " + i + " (" + receivedPacket.getLength() + " bytes)", receivedPacket.getData(), receivedPacket.getLength());
            parsePackets(ByteBuffer.wrap(receivedPacket.getData(), 0, receivedPacket.getLength()), tlsState);
        }
    }

    private void send(LongHeaderPacket longHeaderPacket, String logMessage) throws IOException {
        byte[] packetData = longHeaderPacket.getBytes();
        DatagramPacket datagram = new DatagramPacket(packetData, packetData.length, serverAddress, port);
        socket.send(datagram);
        log.debug("packet sent (" + logMessage + "), pn: " + longHeaderPacket.getPacketNumber(), packetData);
        log.sent(longHeaderPacket);
    }

    /**
     * Generate the initial connection id's for this connection.
     * Note that connection id's might change during the lifetime of a connection, and the dest connection id certainly will.
     * @param srcConnIdLength
     * @param dstConnIdLength
     */
    private void generateConnectionIds(int srcConnIdLength, int dstConnIdLength) {
        ByteBuffer buffer = ByteBuffer.allocate(srcConnIdLength);
        buffer.putLong(random.nextLong());
        sourceConnectionId = new byte[srcConnIdLength];
        buffer.rewind();
        buffer.get(sourceConnectionId);
        log.debug("Source connection id", sourceConnectionId);

        buffer = ByteBuffer.allocate(dstConnIdLength);
        buffer.putLong(random.nextLong());
        destConnectionId = new byte[dstConnIdLength];
        buffer.rewind();
        buffer.get(destConnectionId);
        log.debug("Destination connection id", destConnectionId);
    }

    private void generateInitialKeys() {
        connectionSecrets = new ConnectionSecrets(quicVersion, log);
        connectionSecrets.computeInitialKeys(destConnectionId);
    }

    void parsePackets(ByteBuffer data, TlsState tlsState) throws IOException {
        int packetStart = data.position();

        int flags = data.get();
        int version = data.getInt();
        data.rewind();

        QuicPacket packet;

        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.4:
        // "A Version Negotiation packet ... will appear to be a packet using the long header, but
        //  will be identified as a Version Negotiation packet based on the
        //  Version field having a value of 0."
        if (version == 0) {
            packet = new VersionNegotationPacket().parse(data, log);
            log.received(packet);
            log.info("Server doesn't support " + quicVersion + ", but only: " + ((VersionNegotationPacket) packet).getServerSupportedVersions().stream().collect(Collectors.joining(", ")));
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.5
        // "An Initial packet uses long headers with a type value of 0x7F."
        else if ((flags & 0xff) == 0xff) {
            packet = new InitialPacket(quicVersion, this, tlsState, connectionSecrets).parse(data, log);
            log.received(packet);
            destConnectionId = ((LongHeaderPacket) packet).getSourceConnectionId();
            acknowledge(Initial, packet.getPacketNumber());
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.7
        // "A Retry packet uses a long packet header with a type value of 0x7E."
        else if ((flags & 0xff) == 0xfe) {
            // Retry
            packet = null;
            System.out.println("Ignoring Retry packet");
            return;
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.6
        // "A Handshake packet uses long headers with a type value of 0x7D."
        else if ((flags & 0xff) == 0xfd) {
            packet = new HandshakePacket(quicVersion, this, connectionSecrets, tlsState).parse(data, log);
            log.received(packet);
            acknowledge(Handshake, packet.getPacketNumber());
        }
        else if ((flags & 0xff) == 0xfc) {
            // 0-RTT Protected
            packet = null;
            System.out.println("Ignoring 0-RTT Protected package");
            return;
        }
        else {
            throw new ProtocolError(String.format("Unknown Packet type; flags=%x", flags));
        }
        log.debug("Parsed packet with size " + (data.position() - packetStart) + "; " + data.remaining() + " bytes left.");

        if (data.position() < data.limit()) {
            parsePackets(data.slice(), tlsState);
        }
    }

    public CryptoStream getCryptoStream(EncryptionLevel encryptionLevel) {
        if (cryptoStreams.size() <= encryptionLevel.ordinal()) {
            for (int i = encryptionLevel.ordinal() - cryptoStreams.size(); i >= 0; i--) {
                cryptoStreams.add(new CryptoStream(encryptionLevel, connectionSecrets, tlsState, log));
            }
        }
        return cryptoStreams.get(encryptionLevel.ordinal());
    }

    private void acknowledge(EncryptionLevel encryptionLevel, int packetNumber) throws IOException {
        AckFrame ack = new AckFrame(quicVersion, packetNumber);

        LongHeaderPacket ackPacket = null;
        switch (encryptionLevel) {
            case Initial:
                ackPacket = new InitialPacket(quicVersion, sourceConnectionId, destConnectionId, lastPacketNumber[encryptionLevel.ordinal()]++, ack, connectionSecrets);
                break;
            case Handshake:
                ackPacket = new HandshakePacket(quicVersion, sourceConnectionId, destConnectionId, lastPacketNumber[encryptionLevel.ordinal()]++, ack, connectionSecrets);
                break;
        }
        send(ackPacket, "ack " + packetNumber + " on level " + encryptionLevel);
    }


    // Stub
    private byte[] createClientHello(String host, ECPublicKey publicKey) {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[] {
                (byte) 0x01, // Client Hello
                (byte) 0x00, (byte) 0x01, (byte) 0x27,  // Length 295
                (byte) 0x03, (byte) 0x03,   // Version
                (byte) 0xa0, (byte) 0xad, (byte) 0xf9, (byte) 0x3a, (byte) 0x3c, (byte) 0x70, (byte) 0x19, (byte) 0x37,
                (byte) 0x9b, (byte) 0xd5, (byte) 0x70, (byte) 0x59, (byte) 0x26, (byte) 0x21, (byte) 0x6a, (byte) 0x75,
                (byte) 0xc2, (byte) 0x89, (byte) 0x3a, (byte) 0xed, (byte) 0x3e, (byte) 0x57, (byte) 0xf9, (byte) 0xdf,
                (byte) 0xca, (byte) 0xe5, (byte) 0xd3, (byte) 0x76, (byte) 0x92, (byte) 0x02, (byte) 0xc1, (byte) 0x9f,   // Client random
                (byte) 0x00,  // Session id
                (byte) 0x00, (byte) 0x08,  // Cipher suites length
                (byte) 0x13, (byte) 0x01, (byte) 0x13, (byte) 0x01, (byte) 0x13, (byte) 0x01, (byte) 0x00, (byte) 0xff,  // Cipher suites
                (byte) 0x01, (byte) 0x00,  // Compression methods
                (byte) 0x00, (byte) 0xf6,  // Extension length
                // Quic transport parameters           length 56
                (byte) 0xff, (byte) 0xa5, (byte) 0x00, (byte) 0x38,
                (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x0e, (byte) 0x00, (byte) 0x32, (byte) 0x00, (byte) 0x03,
                (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x1e, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x04,
                (byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x0a, (byte) 0x00, (byte) 0x04,
                (byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x0b, (byte) 0x00, (byte) 0x04,
                (byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x04,
                (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x02,
                (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x08, (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x01,
                // Server name                                length 14
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x0e,
                (byte) 0x00, (byte) 0x0c, (byte) 0x00, (byte) 0x00, (byte) 0x09, (byte) 0x6c, (byte) 0x6f, (byte) 0x63,
                (byte) 0x61, (byte) 0x6c, (byte) 0x68, (byte) 0x6f, (byte) 0x73, (byte) 0x74,
                // ec point formats
                (byte) 0x00, (byte) 0x0b, (byte) 0x00, (byte) 0x04, (byte) 0x03, (byte) 0x00, (byte) 0x01, (byte) 0x02,
                // support groups                        length 10
                (byte) 0x00, (byte) 0x0a, (byte) 0x00, (byte) 0x0a,
                (byte) 0x00, (byte) 0x08, (byte) 0x00, (byte) 0x17, (byte) 0x00, (byte) 0x1d, (byte) 0x00, (byte) 0x18,
                (byte) 0x00, (byte) 0x19,
                // session ticket                length 0
                (byte) 0x00, (byte) 0x23, (byte) 0x00, (byte) 0x00,
                // application layer protocol negotiation  length 8
                (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x08,
                (byte) 0x00, (byte) 0x06, (byte) 0x05, (byte) 0x68, (byte) 0x71, (byte) 0x2d, (byte) 0x31, (byte) 0x34,
                // encrypt than mac
                (byte) 0x00, (byte) 0x16, (byte) 0x00, (byte) 0x00,
                // extended master secret
                (byte) 0x00, (byte) 0x17, (byte) 0x00, (byte) 0x00,
                // signature algorithms               length 30
                (byte) 0x00, (byte) 0x0d, (byte) 0x00, (byte) 0x1e,
                (byte) 0x00, (byte) 0x1c, (byte) 0x04, (byte) 0x03, (byte) 0x05, (byte) 0x03, (byte) 0x06, (byte) 0x03,
                (byte) 0x08, (byte) 0x07, (byte) 0x08, (byte) 0x08, (byte) 0x08, (byte) 0x09, (byte) 0x08, (byte) 0x0a,
                (byte) 0x08, (byte) 0x0b, (byte) 0x08, (byte) 0x04, (byte) 0x08, (byte) 0x05, (byte) 0x08, (byte) 0x06,
                (byte) 0x04, (byte) 0x01, (byte) 0x05, (byte) 0x01, (byte) 0x06, (byte) 0x01,
                // supported versions
                (byte) 0x00, (byte) 0x2b, (byte) 0x00, (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                // psk key exchanges modes
                (byte) 0x00, (byte) 0x2d, (byte) 0x00, (byte) 0x02, (byte) 0x01, (byte) 0x01,
                // key share                                  71 bytes
                (byte) 0x00, (byte) 0x33, (byte) 0x00, (byte) 0x47,
                // key share length: 69
                (byte) 0x00, (byte) 0x45,
                // group
                (byte) 0x00, (byte) 0x17,
                // length: 65
                (byte) 0x00, (byte) 0x41,
                // key
                (byte) 0x04, (byte) 0xf3, (byte) 0x65, (byte) 0xf2, (byte) 0x28, (byte) 0xf6, (byte) 0xac, (byte) 0x00,
                (byte) 0x38, (byte) 0x9f, (byte) 0x99, (byte) 0xa0, (byte) 0x8c, (byte) 0x79, (byte) 0xd5, (byte) 0x35,
                (byte) 0x6b, (byte) 0x61, (byte) 0xb9, (byte) 0x64, (byte) 0x41, (byte) 0xd0, (byte) 0x7d, (byte) 0xa2,
                (byte) 0xa9, (byte) 0xf2, (byte) 0x21, (byte) 0xeb, (byte) 0x32, (byte) 0xa1, (byte) 0xfa, (byte) 0x93,
                (byte) 0x64, (byte) 0xd0, (byte) 0xf6, (byte) 0xb1, (byte) 0x6b, (byte) 0x28, (byte) 0xb9, (byte) 0x04,
                (byte) 0x44, (byte) 0xba, (byte) 0x93, (byte) 0x5d, (byte) 0x7a, (byte) 0x3e, (byte) 0xe6, (byte) 0xf0,
                (byte) 0xfa, (byte) 0x54, (byte) 0x6b, (byte) 0xae, (byte) 0x4e, (byte) 0xe9, (byte) 0x2d, (byte) 0x03,
                (byte) 0xee, (byte) 0xf3, (byte) 0x59, (byte) 0x11, (byte) 0x00, (byte) 0x13, (byte) 0xcd, (byte) 0x45,
                (byte) 0x15
        });
        // Reset position to beginning of key share extension (71 + 4 bytes)
        buffer.position(buffer.limit() - 75);
        // And generate proper key share extension
        KeyShareExtension keyShareExtension = new KeyShareExtension(publicKey, "secp256r1");
        buffer.put(keyShareExtension.getBytes());

        return buffer.array();
    }

}
