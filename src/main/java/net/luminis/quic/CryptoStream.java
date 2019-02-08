/*
 * Copyright © 2019 Peter Doornbosch
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

import net.luminis.tls.*;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;


public class CryptoStream {

    private List<CryptoFrame> frames = new ArrayList<>();
    private final Version quicVersion;
    private final QuicConnection connection;
    private final EncryptionLevel encryptionLevel;
    private final ConnectionSecrets connectionSecrets;
    private TlsState tlsState;
    private final Logger log;


    public CryptoStream(Version quicVersion, QuicConnection connection, EncryptionLevel encryptionLevel, ConnectionSecrets connectionSecrets, TlsState tlsState, Logger log) {
        this.quicVersion = quicVersion;
        this.connection = connection;
        this.encryptionLevel = encryptionLevel;
        this.connectionSecrets = connectionSecrets;
        this.tlsState = tlsState;
        this.log = log;
    }

    public void add(CryptoFrame cryptoFrame) {
        int frameOffset = cryptoFrame.getOffset();
        // Find first frame with offset larger than this and insert before.
        boolean inserted = false;
        for (int i = 0; !inserted && i < frames.size(); i++) {
            if (frames.get(i).getOffset() > frameOffset) {
                // First check whether this frame is not added already
                if (i > 0 && frames.get(i-1).getOffset() == frameOffset) {
                    log.debug(this + " Ignoring duplicate: " + cryptoFrame);
                    return;
                }
                // Insert here.
                frames.add(i, cryptoFrame);
                inserted = true;
            }
        }
        if (! inserted) {
            // So offset is larger (or equal) than all existing frames.
            // First check whether this frame is not added already
            if (frames.size() > 0 && frames.get(frames.size() - 1).getOffset() == frameOffset) {
                log.debug(this + " Ignoring duplicate: " + cryptoFrame);
                return;
            }

            frames.add(cryptoFrame);
        }

        if (contiguousFrames()) {
            // TODO: this parses all frames again, maybe keep a pointer in the stream to where it was successfully parsed.
            ByteBuffer buffer = ByteBuffer.allocate(frames.stream().mapToInt(f -> f.getLength()).sum());
            for (CryptoFrame frame: frames) {
                buffer.put(frame.getCryptoData());
            }
            buffer.rewind();
            try {
                while (buffer.remaining() > 0) {
                    Object msg = HandshakeRecord.parseHandshakeMessage(buffer, tlsState);
                    log.debug(this + " Detected " + msg.getClass().getSimpleName());
                    if (msg instanceof ServerHello) {
                        // Server Hello provides a new secret, so
                        connectionSecrets.computeHandshakeSecrets(tlsState);
                    }
                    else if (msg instanceof EncryptedExtensions) {
                        for (Extension ex: ((EncryptedExtensions) msg).getExtensions()) {
                            if (ex instanceof UnknownExtension) {
                                parseExtension((UnknownExtension) ex);
                            }
                        }
                    }
                    else if (msg instanceof FinishedMessage) {
                        if (tlsState.isServerFinished()) {
                            connection.finishHandshake(tlsState);
                        }
                    }
                    else {
                        log.debug(this + " Ignoring " + msg.getClass().getSimpleName());
                    }
                }
            } catch (BufferUnderflowException notYetEnough) {
                // Don't bother, try later
                log.debug(this + " (Received incomplete crypto message, wait for more)");
            } catch (TlsProtocolException e) {
            }
        }
        else {
            // Wait for more frames
            log.debug(this + " Crypto stream contains non-contiguous frames, wait for more");
        }
    }

    private boolean contiguousFrames() {
        int lastStart = 0;
        for (CryptoFrame frame: frames) {
            if (frame.getOffset() != lastStart) {
                return false;
            }
            lastStart += frame.getLength();
        }
        return true;
    }

    private void parseExtension(UnknownExtension extension) {
        ByteBuffer buffer = ByteBuffer.wrap(extension.getData());
        int extensionType = buffer.getShort();
        buffer.rewind();
        if ((extensionType & 0xffff) == 0xffa5) {
            if (quicVersion.atLeast(Version.IETF_draft_17)) {
                new QuicTransportParametersExtension().parse(buffer, log);
            }
            else {
                new QuicTransportParametersExtensionPreDraft17().parse(buffer, log);
            }
        }
        else {
            log.debug("Unsupported extension!");
        }
    }

    @Override
    public String toString() {
        return "CryptoStream["  + encryptionLevel.name().charAt(0) + "]";
    }
}
