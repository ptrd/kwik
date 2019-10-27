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

import java.nio.ByteBuffer;
import java.time.Instant;

public class NullLogger implements Logger {

    @Override
    public void logDebug(boolean enabled) {
    }

    @Override
    public void logRaw(boolean enabled) {
    }

    @Override
    public void logDecrypted(boolean enabled) {
    }

    @Override
    public void logSecrets(boolean enabled) {
    }

    @Override
    public void logPackets(boolean enabled) {
    }

    @Override
    public void logInfo(boolean enabled) {
    }

    @Override
    public void logStats(boolean enabled) {
    }

    @Override
    public void logRecovery(boolean enabled) {
    }

    @Override
    public void logCongestionControl(boolean enabled) {
    }

    @Override
    public void useRelativeTime(boolean enabled) {
    }

    @Override
    public void debug(String message) {
    }

    @Override
    public void debug(String message, Exception error) {
    }

    @Override
    public void debugWithHexBlock(String message, byte[] data) {
    }

    @Override
    public void debugWithHexBlock(String message, byte[] data, int length) {
    }

    @Override
    public void debug(String message, byte[] data) {
    }

    @Override
    public void info(String message) {
    }

    @Override
    public void info(String message, byte[] data) {
    }

    @Override
    public void received(Instant timeReceived, int datagram, QuicPacket packet) {
    }

    @Override
    public void sent(Instant sent, QuicPacket packet) {
    }

    @Override
    public void secret(String message, byte[] secret) {
    }

    @Override
    public void raw(String message, byte[] data) {
    }

    @Override
    public void raw(String message, ByteBuffer data, int offset, int length) {
    }

    @Override
    public void raw(String message, byte[] data, int length) {
    }

    @Override
    public void decrypted(String message, byte[] data) {
    }

    @Override
    public void decrypted(String message, byte[] data, int length) {
    }

    @Override
    public void decrypted(String message) {
    }

    @Override
    public void encrypted(String message, byte[] data) {
    }

    @Override
    public void error(String message) {
    }

    @Override
    public void error(String message, Throwable error) {
    }

    @Override
    public void stats(String message) {
    }

    @Override
    public void recovery(String message) {
    }

    @Override
    public void cc(String message) {
    }

    @Override
    public void receivedPacketInfo(String toString) {
    }
}

