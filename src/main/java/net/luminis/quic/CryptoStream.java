/*
 * Copyright © 2019, 2020 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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
import net.luminis.quic.log.Logger;
import net.luminis.quic.stream.BaseStream;
import net.luminis.tls.*;
import net.luminis.tls.extension.Extension;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;


public class CryptoStream extends BaseStream {

    private final Version quicVersion;
    private final QuicConnectionImpl connection;
    private final EncryptionLevel encryptionLevel;
    private final ConnectionSecrets connectionSecrets;
    private TlsState tlsState;
    private final Logger log;
    private List<Message> messages;
    private TlsMessageParser tlsMessageParser;
    private boolean msgSizeRead = false;
    private int msgSize;
    private byte msgType;

    public CryptoStream(Version quicVersion, QuicConnectionImpl connection, EncryptionLevel encryptionLevel, ConnectionSecrets connectionSecrets, TlsState tlsState, Logger log) {
        this.quicVersion = quicVersion;
        this.connection = connection;
        this.encryptionLevel = encryptionLevel;
        this.connectionSecrets = connectionSecrets;
        this.tlsState = tlsState;
        this.log = log;

        messages = new ArrayList<>();
        tlsMessageParser = new TlsMessageParser();
    }

    public void add(CryptoFrame cryptoFrame) {
        try {
            if (super.add(cryptoFrame)) {
                int availableBytes = bytesAvailable();
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
                        Message tlsMessage = tlsMessageParser.parse(msgBuffer, tlsState);

                        if (msgBuffer.hasRemaining()) {
                            throw new RuntimeException();  // Must be programming error
                        }
                        messages.add(tlsMessage);
                        processMessage(tlsMessage);
                    }
                }
            } else {
                log.debug("Discarding " + cryptoFrame + ", because stream already parsed to " + readOffset());
            }
        }
        catch (TlsProtocolException tlsError) {
            log.error("Parsing TLS message failed", tlsError);
            throw new ProtocolError("TLS error");
        }
    }

    private void processMessage(Message msg) throws TlsProtocolException {
        log.debug(this + " Detected " + msg.getClass().getSimpleName());
        if (msg instanceof ServerHello) {
            // Server Hello provides a new secret, so
            TlsConstants.CipherSuite selectedCipherSuite = ((ServerHello) msg).getCipherSuite();
            connectionSecrets.computeHandshakeSecrets(tlsState, selectedCipherSuite);
            connection.hasHandshakeKeys();
        } else if (msg instanceof EncryptedExtensions) {
            for (Extension ex : ((EncryptedExtensions) msg).getExtensions()) {
                if (ex instanceof EarlyDataExtension) {
                    connection.setEarlyDataStatus(EarlyDataStatus.Accepted);
                    log.info("Server has accepted early data.");
                }
                else if (ex instanceof UnknownExtension) {
                    parseExtension((UnknownExtension) ex);
                }
            }
        } else if (msg instanceof FinishedMessage) {
            if (tlsState.isServerFinished()) {
                connection.finishHandshake(tlsState);
            }
        } else if (msg instanceof NewSessionTicketMessage) {
            connection.addNewSessionTicket(new NewSessionTicket(tlsState, (NewSessionTicketMessage) msg));
        } else {
            log.debug(this + " Ignoring " + msg.getClass().getSimpleName());
        }
    }

    private void parseExtension(UnknownExtension extension) throws TlsProtocolException {
        ByteBuffer buffer = ByteBuffer.wrap(extension.getData());
        int extensionType = buffer.getShort();
        buffer.rewind();
        if ((extensionType & 0xffff) == 0xffa5) {
            QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(quicVersion);
            try {
                transportParametersExtension.parse(buffer, log);
            } catch (InvalidIntegerEncodingException e) {
                throw new TlsProtocolException("Invalid transport parameter extension");
            }
            connection.setPeerTransportParameters(transportParametersExtension.getTransportParameters());
        }
        else {
            log.debug("Crypto stream: unsupported extension " + extensionType);
        }
    }

    @Override
    public String toString() {
        return "CryptoStream["  + encryptionLevel.name().charAt(0) + "|" + messages.stream()
                .map(msg -> msg.getClass().getSimpleName())
                .map(name -> name.endsWith("Message")? name.substring(0, name.length() - 7): name)
                .collect(Collectors.joining(","))
                + "]";
    }

    public List<Message> getTlsMessages() {
        return messages;
    }

}
