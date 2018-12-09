package net.luminis.quic;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Random;
import java.util.stream.Collectors;

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
    private TlsSession tlsSession;

    public QuicConnection(String host, int port, Version quicVersion) {
        log = new Logger();
        log.debug("Creating connection with " + host + ":" + port);
        this.host = host;
        this.port = port;
        this.quicVersion = quicVersion;
    }

    /**
     * Set up the connection with the server.
     */
    public void connect() throws IOException {
        generateConnectionIds(8, 8);
        generateInitialKeys();

        // Create client hello
        tlsSession = new TlsSession();
        byte[] clientHello = tlsSession.getClientHello();
        // Wrap it in a long header packet
        LongHeaderPacket longHeaderPacket = new InitialPacket(quicVersion, sourceConnectionId, destConnectionId, 0, clientHello, connectionSecrets);
        log.debugWithHexBlock("Sending packet", longHeaderPacket.getBytes());

        DatagramSocket socket = new DatagramSocket();
        DatagramPacket packet = new DatagramPacket(longHeaderPacket.getBytes(), longHeaderPacket.getBytes().length, InetAddress.getByName(host), port);
        socket.send(packet);
        log.debug("packet sent");

        byte[] receiveBuffer = new byte[1500];
        DatagramPacket receivedPacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
        socket.setSoTimeout(5000);
        socket.receive(receivedPacket);

        log.debugWithHexBlock("Received packet (" + receivedPacket.getLength() + " bytes)", receivedPacket.getData(), receivedPacket.getLength());

        parse(ByteBuffer.wrap(receivedPacket.getData(), 0, receivedPacket.getLength()));
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
        connectionSecrets.generate(destConnectionId);
    }

    void parse(ByteBuffer data) {
        int flags = data.get();
        int version = data.getInt();
        data.rewind();

        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.4:
        // "A Version Negotiation packet ... will appear to be a packet using the long header, but
        //  will be identified as a Version Negotiation packet based on the
        //  Version field having a value of 0."
        if (version == 0) {
            VersionNegotationPacket versionNegotationPacket = new VersionNegotationPacket().parse(data, log);
            log.info("Server doesn't support " + quicVersion + ", but only: " + versionNegotationPacket.getServerSupportedVersions().stream().collect(Collectors.joining(", ")));
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.5
        // "An Initial packet uses long headers with a type value of 0x7F."
        else if ((flags & 0xff) == 0xff) {
            new InitialPacket(connectionSecrets).parse(data, log);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.7
        // "A Retry packet uses a long packet header with a type value of 0x7E."
        else if ((flags & 0xff) == 0xfe) {
            // Retry
            System.out.println("Ignoring Retry packet");
            return;
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.6
        // "A Handshake packet uses long headers with a type value of 0x7D."
        else if ((flags & 0xff) == 0xfd) {
            System.out.println("Ignoring handshake packet");
            return;
        }
        else if ((flags & 0xff) == 0xfc) {
            // 0-RTT Protected
            System.out.println("Ignoring 0-RTT Protected package");
            return;
        }
        else {
            throw new ProtocolError(String.format("Unknown Packet type; flags=%x", flags));
        }

        if (data.position() < data.limit()) {
            parse(data.slice());
        }
    }
}
