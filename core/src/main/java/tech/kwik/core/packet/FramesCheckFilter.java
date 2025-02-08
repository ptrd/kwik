/*
 * Copyright © 2025 Peter Doornbosch
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
package tech.kwik.core.packet;

import tech.kwik.core.QuicConstants;
import tech.kwik.core.frame.*;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.log.Logger;

public class FramesCheckFilter extends BasePacketFilter {

    public FramesCheckFilter(PacketFilter next) {
        super(next);
    }

    public FramesCheckFilter(PacketFilter next, Logger log) {
        super(next, log);
    }

    @Override
    public void processPacket(QuicPacket packet, PacketMetaData metaData) throws TransportError {
        checkNotEmpty(packet);

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
        // "An endpoint MUST treat receipt of a frame in a packet type that is not permitted as a connection error
        //  of type PROTOCOL_VIOLATION."
        if (packet instanceof InitialPacket) {
            checkFrames((InitialPacket) packet);
        }
        else if (packet instanceof HandshakePacket) {
            checkFrames((HandshakePacket) packet);
        }
        else if (packet instanceof ZeroRttPacket) {
            checkFrames((ZeroRttPacket) packet);
        }
        else if (packet instanceof ShortHeaderPacket) {
            checkFrames((ShortHeaderPacket) packet);
        }
        next(packet, metaData);
    }

    private void checkFrames(InitialPacket packet) throws TransportError {
        if (! packet.getFrames().stream()
                .allMatch(
                        // ! allMatch => list frames that are permitted
                        frame -> frame instanceof Padding ||
                        frame instanceof PingFrame ||
                        frame instanceof AckFrame ||
                        frame instanceof CryptoFrame ||
                        (frame instanceof ConnectionCloseFrame && ((ConnectionCloseFrame) frame).getFrameType() == 0x1c)
                )) {
            discard(packet, "packet contains frame type that is not permitted");
            throw new TransportError(QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION, "packet contains frame type that is not permitted");
        }
    }

    private void checkFrames(ZeroRttPacket packet) throws TransportError {
        if (packet.getFrames().stream()
                .anyMatch(
                        // anyMatch => list frames that are _not_ permitted
                        frame -> frame instanceof CryptoFrame ||
                        frame instanceof AckFrame ||
                        frame instanceof NewTokenFrame ||
                        frame instanceof PathResponseFrame ||
                        frame instanceof HandshakeDoneFrame)) {
            discard(packet, "packet contains frame type that is not permitted");
            throw new TransportError(QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION, "packet contains frame type that is not permitted");
        }
    }

    private void checkFrames(HandshakePacket packet) throws TransportError {
        if (! packet.getFrames().stream()
                .allMatch(
                        // ! allMatch => list frames that are permitted
                        frame -> frame instanceof Padding ||
                                frame instanceof PingFrame ||
                                frame instanceof AckFrame ||
                                frame instanceof CryptoFrame ||
                                (frame instanceof ConnectionCloseFrame && ((ConnectionCloseFrame) frame).getFrameType() == 0x1c)
                )) {
            discard(packet, "packet contains frame type that is not permitted");
            throw new TransportError(QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION, "packet contains frame type that is not permitted");
        }
    }

    private void checkFrames(ShortHeaderPacket packet) {
        // Intentionally left empty: all frames are permitted
    }

    private void checkNotEmpty(QuicPacket packet) throws TransportError {
        if (packet instanceof RetryPacket || packet instanceof VersionNegotiationPacket) {
            return;
        }

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
        // "An endpoint MUST treat receipt of a packet containing no frames as a connection error of type
        //  PROTOCOL_VIOLATION."
        if (packet.getFrames().isEmpty()) {
            discard(packet, "packet must contain at least one frame");
            throw new TransportError(QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION, "packet must contain at least one frame");
        }
    }
}
