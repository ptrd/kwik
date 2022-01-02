/*
 * Copyright © 2018, 2019, 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.quic;

import net.luminis.quic.crypto.ConnectionSecrets;
import net.luminis.quic.frame.CryptoFrame;
import net.luminis.quic.frame.QuicFrame;
import net.luminis.quic.log.Logger;
import net.luminis.quic.send.Sender;
import net.luminis.quic.stream.BaseStream;
import net.luminis.quic.tls.QuicTransportParametersExtension;
import net.luminis.tls.*;
import net.luminis.tls.extension.Extension;
import net.luminis.tls.handshake.HandshakeMessage;
import net.luminis.tls.handshake.TlsEngine;
import net.luminis.tls.handshake.TlsMessageParser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;


public class CryptoStream extends BaseStream {

    private final Version quicVersion;
    private final EncryptionLevel encryptionLevel;
    private final ProtectionKeysType tlsProtectionType;
    private final ConnectionSecrets connectionSecrets;
    private final Role peerRole;
    private final TlsEngine tlsEngine;
    private final Logger log;
    private final Sender sender;
    private final List<Message> messagesReceived;
    private final List<Message> messagesSent;
    private final TlsMessageParser tlsMessageParser;
    private final List<ByteBuffer> dataToSend;
    private volatile int dataToSendOffset;
    private volatile int sendStreamSize;
    // Only used by add method; thread confinement concurrency control (assuming one receiver thread)
    private boolean msgSizeRead = false;
    private int msgSize;
    private byte msgType;


    public CryptoStream(Version quicVersion, EncryptionLevel encryptionLevel, ConnectionSecrets connectionSecrets, Role role, TlsEngine tlsEngine, Logger log, Sender sender) {
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
    }

    public void add(CryptoFrame cryptoFrame) throws TlsProtocolException {
        try {
            if (super.add(cryptoFrame)) {
                long availableBytes = bytesAvailable();
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
                        read(buffer);
                        msgType = buffer.get(0);
                        buffer.put(0, (byte) 0);  // Mask 1st byte as it contains the TLS handshake msg type
                        buffer.flip();
                        msgSize = buffer.getInt();
                        msgSizeRead = true;
                        availableBytes -= 4;
                    }
                    if (msgSizeRead && availableBytes >= msgSize) {
                        ByteBuffer msgBuffer = ByteBuffer.allocate(4 + msgSize);
                        msgBuffer.putInt(msgSize);
                        msgBuffer.put(0, msgType);
                        int read = read(msgBuffer);
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
            } else {
                log.debug("Discarding " + cryptoFrame + ", because stream already parsed to " + readOffset());
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
        if (QuicTransportParametersExtension.isCodepoint(quicVersion, extensionType & 0xffff)) {
            return new QuicTransportParametersExtension(quicVersion).parse(buffer, peerRole, log);
        }
        else {
            return null;
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

    private String toStringWith(List<Message> messages) {
        return "CryptoStream["  + encryptionLevel.name().charAt(0) + "|" + messages.stream()
                .map(msg -> msg.getClass().getSimpleName())
                .map(name -> name.endsWith("Message")? name.substring(0, name.length() - 7): name)
                .collect(Collectors.joining(","))
                + "]";
    }

    public List<Message> getTlsMessages() {
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

        CryptoFrame frame = new CryptoFrame(quicVersion, dataToSendOffset, frameData);
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
}
