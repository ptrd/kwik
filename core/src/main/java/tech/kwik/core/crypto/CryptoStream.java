/*
 * Copyright © 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
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
package tech.kwik.core.crypto;

import tech.kwik.agent15.ProtectionKeysType;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.InternalErrorAlert;
import tech.kwik.agent15.engine.TlsEngine;
import tech.kwik.agent15.engine.TlsMessageParser;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.handshake.HandshakeMessage;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.frame.CryptoFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.Logger;
import tech.kwik.core.send.Sender;
import tech.kwik.core.stream.ReceiveBuffer;
import tech.kwik.core.stream.ReceiveBufferImpl;
import tech.kwik.core.tls.QuicTransportParametersExtension;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static tech.kwik.core.QuicConstants.TransportErrorCode.CRYPTO_BUFFER_EXCEEDED;


public class CryptoStream {

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-cryptographic-message-buffe
    // "Implementations MUST support buffering at least 4096 bytes of data received in out-of-order CRYPTO frames."
    public final static int MAX_STREAM_GAP = 4096;

    private final VersionHolder quicVersion;
    private final EncryptionLevel encryptionLevel;
    private final ProtectionKeysType tlsProtectionType;
    private final ConnectionSecrets connectionSecrets;
    private final Role peerRole;
    private final TlsEngine tlsEngine;
    private final Logger log;
    private final Sender sender;
    private final ReceiveBuffer receiveBuffer;
    private final List<HandshakeMessage> messagesReceived;
    private final List<HandshakeMessage> messagesSent;
    private final TlsMessageParser tlsMessageParser;
    private final List<ByteBuffer> dataToSend;
    private final int maxMessageSize;
    private volatile int dataToSendOffset;
    private volatile int sendStreamSize;
    // Only used by add method; thread confinement concurrency control (assuming one receiver thread)
    private boolean msgSizeRead = false;
    private int msgSize;
    private byte msgType;
    private int readOffset;

    public CryptoStream(VersionHolder quicVersion, EncryptionLevel encryptionLevel, ConnectionSecrets connectionSecrets, Role role, TlsEngine tlsEngine, Logger log, Sender sender) {
        this.quicVersion = quicVersion;
        this.encryptionLevel = encryptionLevel;
        this.connectionSecrets = connectionSecrets;
        peerRole = role.other();
        this.tlsEngine = tlsEngine;
        this.log = log;
        this.sender = sender;

        tlsProtectionType =
                encryptionLevel == EncryptionLevel.Handshake? ProtectionKeysType.Handshake:
                        encryptionLevel == EncryptionLevel.App? ProtectionKeysType.Application:
                                ProtectionKeysType.None;
        messagesReceived = new ArrayList<>();
        messagesSent = new ArrayList<>();
        tlsMessageParser = new TlsMessageParser(this::quicExtensionsParser);
        dataToSend = new ArrayList<>();
        maxMessageSize = determineMaxMessageSize(role, encryptionLevel);
        receiveBuffer = new ReceiveBufferImpl();
    }

    public void add(CryptoFrame cryptoFrame) throws TlsProtocolException, TransportError {
        try {
            boolean newContent = receiveBuffer.add(cryptoFrame);
            long availableBytes = receiveBuffer.bytesAvailable();
            long contiguousBytes = readOffset + availableBytes;
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-cryptographic-message-buffe
            // "Implementations MUST support buffering at least 4096 bytes of data received in out-of-order CRYPTO frames."
            if (cryptoFrame.getUpToOffset() - contiguousBytes > MAX_STREAM_GAP) {
                throw new TransportError(CRYPTO_BUFFER_EXCEEDED);
            }
            if (newContent) {
                // Because the stream may not have enough bytes available to read the whole message, but enough to
                // read the size, the msg size read must be remembered for the next invocation of this method.
                // So, when this method is called, either one of the following cases holds:
                // - msg size was read last time, but not the message
                // - no msg size and (thus) no msg was read last time (or both where read, leading to the same state)
                // The boolean msgSizeRead is used to differentiate these two cases.
                while (msgSizeRead && availableBytes >= msgSize || !msgSizeRead && availableBytes >= 4) {
                    if (!msgSizeRead && availableBytes >= 4) {
                        // Determine message length (a TLS Handshake message starts with 1 byte type and 3 bytes length)
                        ByteBuffer buffer = ByteBuffer.allocate(4);
                        readOffset += receiveBuffer.read(buffer);
                        msgType = buffer.get(0);
                        buffer.put(0, (byte) 0);  // Mask 1st byte as it contains the TLS handshake msg type
                        buffer.flip();
                        msgSize = buffer.getInt();
                        if (msgSize > maxMessageSize) {
                            throw new InternalErrorAlert("TLS message size too large: " + msgSize);
                        }
                        msgSizeRead = true;
                        availableBytes -= 4;
                    }
                    if (msgSizeRead && availableBytes >= msgSize) {
                        ByteBuffer msgBuffer = ByteBuffer.allocate(4 + msgSize);
                        msgBuffer.putInt(msgSize);
                        msgBuffer.put(0, msgType);
                        int read = receiveBuffer.read(msgBuffer);
                        readOffset += read;
                        availableBytes -= read;
                        msgSizeRead = false;

                        msgBuffer.flip();
                        HandshakeMessage tlsMessage = tlsMessageParser.parseAndProcessHandshakeMessage(msgBuffer, tlsEngine, tlsProtectionType);

                        if (msgBuffer.hasRemaining()) {
                            throw new RuntimeException();  // Must be programming error
                        }
                        messagesReceived.add(tlsMessage);
                    }
                }
            }
            else {
                log.debug("Discarding " + cryptoFrame + ", because stream already parsed to " + receiveBuffer.readOffset());
            }
        }
        catch (IOException e) {
            // Impossible, because the kwik implementation of the ClientMessageSender does not throw IOException.
            throw new RuntimeException();
        }
    }

    Extension quicExtensionsParser(ByteBuffer buffer, TlsConstants.HandshakeType context) throws TlsProtocolException {
        buffer.mark();
        int extensionType = buffer.getShort();
        buffer.reset();
        if (QuicTransportParametersExtension.isCodepoint(quicVersion.getVersion(), extensionType & 0xffff)) {
            return new QuicTransportParametersExtension(quicVersion.getVersion()).parse(buffer, peerRole, log);
        }
        else {
            return null;
        }
    }

    private int determineMaxMessageSize(Role role, EncryptionLevel encryptionLevel) {
        // Of course, this is violating the layer separation between QUIC and TLS, but it serves a good purpose:
        // avoid excessive use of memory by malicious peers.
        switch (encryptionLevel) {
            case Initial:
                // Client Hello, Server Hello
                return 3000;
            case Handshake:
                // Client: Certificate; Server: Finished
                return role == Role.Client ? 16384 : 100;
            case App:
                // Client: New Session Ticket; Server: -
                return role == Role.Client ? 65535 : 300;
            case ZeroRTT:
                // 0-RTT does not allow crypo frames.
                return 0;
            default:
                // Impossible
                return 0;
        }
    }

    @Override
    public String toString() {
        return toStringWith(Collections.emptyList());
    }

    /**
     * Return string representation of this crypto stream, including all messages that are received.
     * @return
     */
    public String toStringReceived() {
        return toStringWith(messagesReceived);
    }

    /**
     * Return string representation of this crypto stream, including all messages that are sent.
     * @return
     */
    public String toStringSent() {
        return toStringWith(messagesSent);
    }

    private String toStringWith(List<HandshakeMessage> messages) {
        return "CryptoStream["  + encryptionLevel.name().charAt(0) + "|" + messages.stream()
                .map(msg -> msg.getClass().getSimpleName())
                .map(name -> name.endsWith("Message")? name.substring(0, name.length() - 7): name)
                .collect(Collectors.joining(","))
                + "]";
    }

    public List<HandshakeMessage> getTlsMessages() {
        return messagesReceived;
    }

    public void write(HandshakeMessage message, boolean flush) {
        write(message.getBytes());
        if (flush) {
            sender.flush();
        }
        messagesSent.add(message);
    }

    void write(byte[] data) {
        dataToSend.add(ByteBuffer.wrap(data));
        sendStreamSize += data.length;
        sender.send(this::sendFrame, 10, encryptionLevel, this::retransmitCrypto);  // Caller should flush sender.
    }

    private QuicFrame sendFrame(int maxSize) {
        int leftToSend = sendStreamSize - dataToSendOffset;
        int bytesToSend = Integer.min(leftToSend, maxSize - 10);
        if (bytesToSend == 0) {
            return null;
        }
        if (bytesToSend < leftToSend) {
            // Need (at least) another frame to send all data. Because current method is the sender callback, flushing sender is not necessary.
            sender.send(this::sendFrame, 10, encryptionLevel, this::retransmitCrypto);
        }

        byte[] frameData = new byte[bytesToSend];
        int frameDataOffset = 0;
        while (frameDataOffset < bytesToSend) {
            int bytesToCopy = Integer.min(bytesToSend - frameDataOffset, dataToSend.get(0).remaining());
            dataToSend.get(0).get(frameData, frameDataOffset, bytesToCopy);
            if (dataToSend.get(0).remaining() == 0) {
                dataToSend.remove(0);
            }
            frameDataOffset += bytesToCopy;
        }

        CryptoFrame frame = new CryptoFrame(quicVersion.getVersion(), dataToSendOffset, frameData);
        dataToSendOffset += bytesToSend;
        return frame;
    }

    private void retransmitCrypto(QuicFrame cryptoFrame) {
        log.recovery("Retransmitting " + cryptoFrame + " on level " + encryptionLevel);
        sender.send(cryptoFrame, encryptionLevel, this::retransmitCrypto);
    }

    public void reset() {
        dataToSendOffset = 0;
        sendStreamSize = 0;
        dataToSend.clear();
    }

    public EncryptionLevel getEncryptionLevel() {
        return encryptionLevel;
    }
}
