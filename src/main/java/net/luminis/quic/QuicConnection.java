package net.luminis.quic;

import net.luminis.tls.*;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static net.luminis.quic.EncryptionLevel.*;
import static net.luminis.tls.Tls13.generateKeys;


/**
 * Creates and maintains a QUIC connection with a QUIC server.
 */
public class QuicConnection implements PacketProcessor {

    private final Logger log;
    private final Version quicVersion;
    private final Random random = new Random();
    private final String host;
    private final int port;
    private final TlsState tlsState;
    private final DatagramSocket socket;
    private final InetAddress serverAddress;
    private final int[] lastPacketNumber = new int[EncryptionLevel.values().length];
    private final Sender sender;
    private final Receiver receiver;
    private volatile int receivedPacketCounter;
    private volatile byte[] sourceConnectionId;
    private volatile byte[] destConnectionId;
    private final ConnectionSecrets connectionSecrets;
    private final List<CryptoStream> cryptoStreams = new ArrayList<>();
    private final Map<Integer, QuicStream> streams;
    private int nextStreamId;


    public QuicConnection(String host, int port, Version quicVersion, Logger log) throws UnknownHostException, SocketException {
        log.info("Creating connection with " + host + ":" + port + " with " + quicVersion);
        this.host = host;
        this.port = port;
        serverAddress = InetAddress.getByName(host);
        this.quicVersion = quicVersion;
        this.log = log;

        socket = new DatagramSocket();
        sender = new Sender(socket, 1500, log, serverAddress, port);
        receiver = new Receiver(socket, 1500, log);
        tlsState = new QuicTlsState();
        connectionSecrets = new ConnectionSecrets(quicVersion, log);
        streams = new ConcurrentHashMap<>();
    }

    /**
     * Set up the connection with the server.
     */
    public synchronized void connect() throws IOException {
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

        receiver.start();
        sender.start();

        byte[] clientHello = createClientHello(host, publicKey);
        tlsState.clientHelloSend(privateKey, clientHello);

        LongHeaderPacket clientHelloPacket = new InitialPacket(quicVersion, sourceConnectionId, destConnectionId, getNextPacketNumber(Initial), new CryptoFrame(clientHello), connectionSecrets);
        sender.send(clientHelloPacket, "client hello");

        boolean handshaking = true;
        while (handshaking) {     // TODO: and not timed out
            try {
                RawPacket rawPacket = receiver.get(5);
                if (rawPacket != null) {
                    Duration processDelay = Duration.between(rawPacket.getTimeReceived(), Instant.now());
                    log.raw("Start processing packet " + ++receivedPacketCounter + " (" + rawPacket.getLength() + " bytes)", rawPacket.getData(), 0, rawPacket.getLength());
                    log.debug("Process delay: " + processDelay);

                    parsePackets(rawPacket.getData());

                    if (tlsState.isServerFinished()) {
                        FinishedMessage finishedMessage = new FinishedMessage(tlsState);
                        CryptoFrame cryptoFrame = new CryptoFrame(finishedMessage.getBytes());
                        LongHeaderPacket finishedPacket = new HandshakePacket(quicVersion, sourceConnectionId, destConnectionId, getNextPacketNumber(Handshake), cryptoFrame, connectionSecrets);
                        log.debugWithHexBlock("Sending packet", finishedPacket.getBytes());
                        sender.send(finishedPacket, "client finished");
                        tlsState.computeApplicationSecrets();
                        connectionSecrets.computeApplicationSecrets(tlsState);

                        handshaking = false;
                    }
                }
                else {
                    throw new SocketTimeoutException();
                }
            } catch (InterruptedException e) {
                throw new SocketTimeoutException();
            }
        }
        log.debug("Handshake finished");

        startReceiverLoop();
    }

    private void startReceiverLoop() {
        Thread receiverThread = new Thread(this::receiveAndProcessPackets, "receiver-loop");
        receiverThread.setDaemon(true);
        receiverThread.start();
    }

    private void receiveAndProcessPackets() {
        Thread currentThread = Thread.currentThread();
        try {
            while (! currentThread.isInterrupted()) {
                RawPacket rawPacket = receiver.get(15);
                if (rawPacket != null) {
                    Duration processDelay = Duration.between(rawPacket.getTimeReceived(), Instant.now());
                    log.raw("Start processing packet " + ++receivedPacketCounter + " (" + rawPacket.getLength() + " bytes)", rawPacket.getData(), 0, rawPacket.getLength());
                    log.debug("Process delay: " + processDelay);

                    parsePackets(rawPacket.getData());
                }
            }
        } catch (InterruptedException e) {
            log.debug("Terminating receiver loop");
        }
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
        connectionSecrets.computeInitialKeys(destConnectionId);
    }

    void parsePackets(ByteBuffer data) {
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
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.5
        // "An Initial packet uses long headers with a type value of 0x7F."
        else if ((flags & 0xff) == 0xff) {
            packet = new InitialPacket(quicVersion).parse(data, connectionSecrets, log);
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.7
        // "A Retry packet uses a long packet header with a type value of 0x7E."
        else if ((flags & 0xff) == 0xfe) {
            // Retry packet....
            throw new NotYetImplementedException();
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.6
        // "A Handshake packet uses long headers with a type value of 0x7D."
        else if ((flags & 0xff) == 0xfd) {
            packet = new HandshakePacket(quicVersion).parse(data, connectionSecrets, log);
        }
        else if ((flags & 0xff) == 0xfc) {
            // 0-RTT Protected
            throw new NotYetImplementedException();
        }
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.3
        // "The most significant bit (0x80) of octet 0 is set to 0 for the short header."
        else if ((flags & 0x80) == 0x00) {
            // ShortHeader
            packet = new ShortHeaderPacket(quicVersion).parse(data, this, connectionSecrets, log);
        }
        else {
            throw new ProtocolError(String.format("Unknown Packet type; flags=%x", flags));
        }
        log.received(packet);
        log.debug("Parsed packet with size " + (data.position() - packetStart) + "; " + data.remaining() + " bytes left.");

        packet.accept(this);
        try {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.4
            // "A Version Negotiation packet cannot be explicitly acknowledged in an
            //   ACK frame by a client.  Receiving another Initial packet implicitly
            //   acknowledges a Version Negotiation packet."
            if (! (packet instanceof VersionNegotationPacket)) {
                acknowledge(packet.getEncryptionLevel(), packet.getPacketNumber());
            }
        } catch (IOException e) {
            handleIOError(e);
        }

        if (data.position() < data.limit()) {
            parsePackets(data.slice());
        }
    }

    private CryptoStream getCryptoStream(EncryptionLevel encryptionLevel) {
        if (cryptoStreams.size() <= encryptionLevel.ordinal()) {
            for (int i = encryptionLevel.ordinal() - cryptoStreams.size(); i >= 0; i--) {
                cryptoStreams.add(new CryptoStream(encryptionLevel, connectionSecrets, tlsState, log));
            }
        }
        return cryptoStreams.get(encryptionLevel.ordinal());
    }

    private void acknowledge(EncryptionLevel encryptionLevel, int packetNumber) throws IOException {
        AckFrame ack = new AckFrame(quicVersion, packetNumber);

        QuicPacket ackPacket = null;
        switch (encryptionLevel) {
            case Initial:
                ackPacket = new InitialPacket(quicVersion, sourceConnectionId, destConnectionId, getNextPacketNumber(encryptionLevel), ack, connectionSecrets);
                break;
            case Handshake:
                ackPacket = new HandshakePacket(quicVersion, sourceConnectionId, destConnectionId, getNextPacketNumber(encryptionLevel), ack, connectionSecrets);
                break;
            case App:
                ackPacket = new ShortHeaderPacket(quicVersion, destConnectionId, getNextPacketNumber(encryptionLevel), ack, connectionSecrets);
                break;
        }
        sender.send(ackPacket, "ack " + packetNumber + " on level " + encryptionLevel);
    }

    private int getNextPacketNumber(EncryptionLevel initial) {
        synchronized (lastPacketNumber) {
            return lastPacketNumber[initial.ordinal()]++;
        }
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
                new ApplicationLayerProtocolNegotiationExtension("hq-15"),
        };
        return new ClientHello(host, publicKey, compatibilityMode, supportedCiphers, quicExtensions).getBytes();
    }

    @Override
    public void process(InitialPacket packet) {
        destConnectionId = packet.getSourceConnectionId();
        processFrames(packet);
    }

    @Override
    public void process(HandshakePacket packet) {
        processFrames(packet);
    }

    @Override
    public void process(LongHeaderPacket packet) {
        processFrames(packet);
    }

    @Override
    public void process(ShortHeaderPacket packet) {
        processFrames(packet);
    }

    @Override
    public void process(VersionNegotationPacket packet) {
        log.info("Server doesn't support " + quicVersion + ", but only: " + ((VersionNegotationPacket) packet).getServerSupportedVersions().stream().collect(Collectors.joining(", ")));
        throw new VersionNegationFailure();
    }

    void processFrames(QuicPacket packet) {
        for (QuicFrame frame: packet.getFrames()) {
            if (frame instanceof CryptoFrame) {
                getCryptoStream(packet.getEncryptionLevel()).add((CryptoFrame) frame);
            }
            else if (frame instanceof AckFrame) {
                sender.process(frame, packet.getEncryptionLevel());
            }
            else if (frame instanceof StreamFrame) {
                int streamId = ((StreamFrame) frame).getStreamId();
                QuicStream stream = streams.get(streamId);
                if (stream != null) {
                    stream.add((StreamFrame) frame);
                }
                else {
                    // TODO: could be a server initiated stream.
                    log.error("Receiving frame for non-existant stream " + streamId);
                }
            }
            else {
                log.debug("Ignoring " + frame);
            }
        }
    }

    private void handleIOError(IOException e) {
        System.out.println("Fatal: IO error " + e);
        System.exit(1);
    }

    public QuicStream createStream(boolean bidirectional) {
        int streamId = generateClientStreamId(bidirectional);
        QuicStream stream = new QuicStream(streamId, this, log);
        streams.put(streamId, stream);
        return stream;
    }

    public void close() {
        sender.shutdown();
        // TODO
    }

    private synchronized int generateClientStreamId(boolean bidirectional) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-2.1:
        // "0x0  | Client-Initiated, Bidirectional"
        int id = (nextStreamId << 2) + 0x00;
        nextStreamId++;
        return id;
    }

    void send(StreamFrame streamFrame) throws IOException {
        QuicPacket packet = new ShortHeaderPacket(quicVersion, destConnectionId, getNextPacketNumber(App), streamFrame, connectionSecrets);
        sender.send(packet, "application data");
    }

    int getMaxPacketSize() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-14.1:
        // "An endpoint SHOULD use Datagram Packetization Layer PMTU Discovery
        //   ([DPLPMTUD]) or implement Path MTU Discovery (PMTUD) [RFC1191]
        //   [RFC8201] ..."
        // "In the absence of these mechanisms, QUIC endpoints SHOULD NOT send IP
        //   packets larger than 1280 bytes.  Assuming the minimum IP header size,
        //   this results in a QUIC maximum packet size of 1232 bytes for IPv6 and
        //   1252 bytes for IPv4."
        // As it is not know (yet) whether running over IP4 or IP6, take the smallest of the two:
        return 1232;
    }

    int getMaxShortHeaderPacketOverhead() {
        return 1  // flag byte
                + destConnectionId.length
                + 4  // max packet number size, in practice this will be mostly 1
                + 16 // encryption overhead
        ;
    }
}
