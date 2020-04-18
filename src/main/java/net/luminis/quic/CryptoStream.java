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

import net.luminis.quic.frame.CryptoFrame;
import net.luminis.quic.log.Logger;
import net.luminis.tls.*;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;


public class CryptoStream {

    private SortedSet<CryptoFrame> frames = new TreeSet<>();
    private final Version quicVersion;
    private final QuicConnectionImpl connection;
    private final EncryptionLevel encryptionLevel;
    private final ConnectionSecrets connectionSecrets;
    private TlsState tlsState;
    private final Logger log;
    private List<Message> messages;
    private TlsMessageParser tlsMessageParser;
    private int parsedToOffset = 0;


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
            if (cryptoFrame.getUpToOffset() > parsedToOffset) {
                frames.add(cryptoFrame);

                int availableBytes = bytesAvailable();
                while (availableBytes >= 4) {
                    // Determine message length (a TLS Handshake message starts with 1 byte type and 3 bytes length)
                    ByteBuffer buffer = ByteBuffer.allocate(4);
                    read(buffer);
                    buffer.put(0, (byte) 0);
                    buffer.rewind();
                    int msgSize = buffer.getInt();

                    if (availableBytes >= 4 + msgSize) {
                        ByteBuffer msgBuffer = ByteBuffer.allocate(4 + msgSize);
                        int read = read(msgBuffer);
                        msgBuffer.rewind();
                        Message tlsMessage = tlsMessageParser.parse(msgBuffer, tlsState);

                        if (msgBuffer.limit() - msgBuffer.position() > 0) {
                            throw new RuntimeException();  // Must be programming error
                        }
                        parsedToOffset += read;
                        availableBytes -= read;
                        removeParsedFrames();

                        messages.add(tlsMessage);
                        processMessage(tlsMessage);
                    } else {
                        log.debug("Cannot parse message yet, need " + (4 + msgSize) + " bytes; available: " + availableBytes);
                        break;
                    }
                }
            } else {
                log.debug("Discarding " + cryptoFrame + ", because stream already parsed to " + parsedToOffset);
            }
        }
        catch (TlsProtocolException tlsError) {
            log.error("Parsing TLS message failed", tlsError);
            throw new ProtocolError("TLS error");
        }
    }

    private int bytesAvailable() {
        if (frames.isEmpty()) {
            return 0;
        }
        else {
            int available = 0;
            int readUpTo = parsedToOffset;
            Iterator<CryptoFrame> iterator = frames.iterator();

            while (iterator.hasNext()) {
                CryptoFrame nextFrame = iterator.next();
                if (nextFrame.getOffset() <= readUpTo) {
                    if (nextFrame.getUpToOffset() > readUpTo) {
                        available += nextFrame.getUpToOffset() - readUpTo;
                        readUpTo = nextFrame.getUpToOffset();
                    }
                } else {
                    break;
                }
            }
            return available;
        }
    }

    private int read(ByteBuffer buffer) {
        if (frames.isEmpty()) {
            return 0;
        }
        else {
            int read = 0;
            int readUpTo = parsedToOffset;
            Iterator<CryptoFrame> iterator = frames.iterator();

            while (iterator.hasNext() && buffer.remaining() > 0) {
                CryptoFrame nextFrame = iterator.next();
                if (nextFrame.getOffset() <= readUpTo) {
                    if (nextFrame.getUpToOffset() > readUpTo) {
                        int available = nextFrame.getOffset() - readUpTo + nextFrame.getLength();
                        int bytesToRead = Integer.min(buffer.limit() - buffer.position(), available);
                        buffer.put(nextFrame.getCryptoData(), readUpTo - nextFrame.getOffset(), bytesToRead);
                        readUpTo += bytesToRead;
                        read += bytesToRead;
                    }
                } else {
                    break;
                }
            }
            return read;
        }
    }

    private void removeParsedFrames() {
        Iterator<CryptoFrame> iterator = frames.iterator();
        while (iterator.hasNext()) {
            if (iterator.next().getUpToOffset() <= parsedToOffset) {
                iterator.remove();
            }
            else {
                break;
            }
        }
    }

    private void processMessage(Message msg) throws TlsProtocolException {
        log.debug(this + " Detected " + msg.getClass().getSimpleName());
        if (msg instanceof ServerHello) {
            // Server Hello provides a new secret, so
            connectionSecrets.computeHandshakeSecrets(tlsState);
            connection.hasHandshakeKeys();
        } else if (msg instanceof EncryptedExtensions) {
            for (Extension ex : ((EncryptedExtensions) msg).getExtensions()) {
                if (ex instanceof UnknownExtension) {
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
