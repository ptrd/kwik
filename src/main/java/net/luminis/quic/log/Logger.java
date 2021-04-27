/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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
package net.luminis.quic.log;

import net.luminis.quic.EncryptionLevel;
import net.luminis.quic.packet.QuicPacket;
import net.luminis.quic.qlog.QLog;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;

public interface Logger {

    enum TimeFormat {
        Short,
        Long
    }

    void logDebug(boolean enabled);

    void logRaw(boolean enabled);

    void logDecrypted(boolean enabled);

    void logSecrets(boolean enabled);

    void logPackets(boolean enabled);

    void logInfo(boolean enabled);

    void logWarning(boolean enabled);

    void logStats(boolean enabled);

    void logRecovery(boolean enabled);

    void logCongestionControl(boolean enabled);

    boolean logFlowControl();

    void logFlowControl(boolean enabled);

    void useRelativeTime(boolean enabled);

    void timeFormat(TimeFormat aLong);

    void debug(String message);

    void debug(String message, Exception error);

    void debugWithHexBlock(String message, byte[] data);

    void debugWithHexBlock(String message, byte[] data, int length);

    void debug(String message, byte[] data);

    void warn(String message);

    void info(String message);

    void info(String message, byte[] data);

    void received(Instant timeReceived, int datagram, QuicPacket packet);

    void received(Instant timeReceived, int datagram, EncryptionLevel encryptionLevel, byte[] dcid, byte[] scid);

    void sent(Instant sent, QuicPacket packet);

    void sent(Instant sent, List<QuicPacket> packets);

    void secret(String message, byte[] secret);

    void raw(String message, byte[] data);

    void raw(String message, ByteBuffer data, int offset, int length);

    void raw(String message, byte[] data, int length);

    void decrypted(String message, byte[] data);

    void decrypted(String message, byte[] data, int length);

    void decrypted(String message);

    void encrypted(String message, byte[] data);

    void error(String message);

    void error(String message, Throwable error);

    void stats(String message);

    void recovery(String message);

    void recovery(String format, Instant lossTime);

    void cc(String message);

    void fc(String message);

    void receivedPacketInfo(String toString);

    QLog getQLog();
}
