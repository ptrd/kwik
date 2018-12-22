package net.luminis.quic;

import net.luminis.tls.HandshakeRecord;
import net.luminis.tls.ServerHello;
import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.TlsState;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;


public class CryptoStream {

    private List<CryptoFrame> frames = new ArrayList<>();
    private final ConnectionSecrets connectionSecrets;
    private TlsState tlsState;
    private final Logger log;

    public CryptoStream(ConnectionSecrets connectionSecrets, TlsState tlsState, Logger log) {
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
                    log.debug("Ignoring duplicate: " + cryptoFrame);
                    return;
                }
                // Insert here.
                frames.add(i, cryptoFrame);
                inserted = true;
            }
        }
        if (! inserted) {
            // So offset is larger than all existing frames.
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
                    if (msg instanceof ServerHello) {
                        // Server Hello provides a new secret, so
                        connectionSecrets.serverSecrets.recompute(tlsState);
                    } else {
                        log.debug("Detected " + msg.getClass().getSimpleName());
                    }
                }
            } catch (BufferUnderflowException notYetEnough) {
                // Don't bother, try later
                log.debug("(Received incomplete crypto message, wait for more)");
            } catch (TlsProtocolException e) {
            }
        }
        else {
            // Wait for more frames
            log.debug("Crypto stream contains non-contiguos frames, wait for more");
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
}
