package net.luminis.quic;

import net.luminis.tls.*;

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

import static net.luminis.quic.EncryptionLevel.*;
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
    private boolean clientFinishedSent;


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
        for (int i = 0; i < 9; i++) {
            receivedPacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
            socket.receive(receivedPacket);
            log.debugWithHexBlock("Received packet " + i + " (" + receivedPacket.getLength() + " bytes)", receivedPacket.getData(), receivedPacket.getLength());
            parsePackets(ByteBuffer.wrap(receivedPacket.getData(), 0, receivedPacket.getLength()), tlsState);

            if (tlsState.isServerFinished() && ! clientFinishedSent) {
                FinishedMessage finishedMessage = new FinishedMessage(tlsState);
                CryptoFrame cryptoFrame = new CryptoFrame(finishedMessage.getBytes());
                LongHeaderPacket finishedPacket = new HandshakePacket(quicVersion, sourceConnectionId, destConnectionId, lastPacketNumber[Handshake.ordinal()]++, cryptoFrame, connectionSecrets);
                log.debugWithHexBlock("Sending packet", finishedPacket.getBytes());
                send(finishedPacket, "client finished");
                clientFinishedSent = true;
                tlsState.computeApplicationSecrets();
                connectionSecrets.computeApplicationSecrets(tlsState);

                // At this point, application data can be sent.
                StreamFrame stream0 = new StreamFrame(0, "GET /index.html\r\n");
                QuicPacket packet = new ShortHeaderPacket(quicVersion, destConnectionId, lastPacketNumber[App.ordinal()]++, stream0, connectionSecrets);
                send(packet, "application data");
            }
        }
    }

    private void send(QuicPacket packet, String logMessage) throws IOException {
        byte[] packetData = packet.getBytes();
        DatagramPacket datagram = new DatagramPacket(packetData, packetData.length, serverAddress, port);
        socket.send(datagram);
        log.debug("packet sent (" + logMessage + "), pn: " + packet.getPacketNumber(), packetData);
        log.sent(packet);
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
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.3
        // "The most significant bit (0x80) of octet 0 is set to 0 for the short header."
        else if ((flags & 0x80) == 0x00) {
            // ShortHeader
            packet = new ShortHeaderPacket(quicVersion).parse(data, this, connectionSecrets, tlsState, log);
            log.received(packet);
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

    public byte[] getSourceConnectionId() {
        return sourceConnectionId;
    }

    private byte[] createClientHello(String host, ECPublicKey publicKey) {
        boolean compatibilityMode = false;
        byte[][] supportedCiphers = new byte[][]{ TlsConstants.TLS_AES_128_GCM_SHA256 };

        Extension[] quicExtensions = new Extension[] {
                new QuicTransportParametersExtension(quicVersion),
                new ECPointFormatExtension(),
        };
        return new ClientHello(host, publicKey, compatibilityMode, supportedCiphers, quicExtensions).getBytes();
    }
}
