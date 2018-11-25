package net.luminis.quic;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Random;

/**
 * Creates and maintains a QUIC connection with a QUIC server.
 */
public class QuicConnection {

    private Logger log;
    private final Version quicVersion = Version.IETF_draft_14;
    private final Random random = new Random();
    private final String host;
    private final int port;
    private byte[] sourceConnectionId;
    private byte[] destConnectionId;
    private ConnectionSecrets connectionSecrets;
    private TlsSession tlsSession;

    public QuicConnection(String host, int port) {
        log = new Logger();
        log.debug("Creating connection with " + host + ":" + port);
        this.host = host;
        this.port = port;
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

        log.debugWithHexBlock("Received packet", receivedPacket.getData(), receivedPacket.getLength());

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


}
