/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.log;

import net.luminis.quic.core.EncryptionLevel;
import net.luminis.quic.packet.QuicPacket;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;

public class LogProxy implements Logger {

    private final QLog qlogFrontEnd;
    private Logger proxiedLogger;

    public LogProxy(Logger log, byte[] originalDestinationConnectionId) {
        this.proxiedLogger = log;
        qlogFrontEnd = loadImplementation(originalDestinationConnectionId);
    }

    private QLog loadImplementation(byte[] originalDestinationConnectionId) {
        try {
            Class clazz = this.getClass().getClassLoader().loadClass("net.luminis.quic.qlog.QLogFrontEnd");
            Constructor constructor = clazz.getConstructor(byte[].class);
            return (QLog) constructor.newInstance(originalDestinationConnectionId);
        }
        catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            return new NullQLog();
        }
    }

    @Override
    public void logDebug(boolean enabled) {
        proxiedLogger.logDebug(enabled);
    }

    @Override
    public void logRaw(boolean enabled) {
        proxiedLogger.logRaw(enabled);
    }

    @Override
    public void logDecrypted(boolean enabled) {
        proxiedLogger.logDecrypted(enabled);
    }

    @Override
    public void logSecrets(boolean enabled) {
        proxiedLogger.logSecrets(enabled);
    }

    @Override
    public void logPackets(boolean enabled) {
        proxiedLogger.logPackets(enabled);
    }

    @Override
    public void logInfo(boolean enabled) {
        proxiedLogger.logInfo(enabled);
    }

    @Override
    public void logWarning(boolean enabled) {
        proxiedLogger.logWarning(enabled);
    }

    @Override
    public void logStats(boolean enabled) {
        proxiedLogger.logStats(enabled);
    }

    @Override
    public void logRecovery(boolean enabled) {
        proxiedLogger.logRecovery(enabled);
    }

    @Override
    public boolean logRecovery() {
        return proxiedLogger.logRecovery();
    }

    @Override
    public void logCongestionControl(boolean enabled) {
        proxiedLogger.logCongestionControl(enabled);
    }

    @Override
    public boolean logFlowControl() {
        return proxiedLogger.logFlowControl();
    }

    @Override
    public void logFlowControl(boolean enabled) {
        proxiedLogger.logFlowControl(enabled);
    }

    @Override
    public void useRelativeTime(boolean enabled) {
        proxiedLogger.useRelativeTime(enabled);
    }

    @Override
    public void timeFormat(TimeFormat aLong) {

    }

    @Override
    public void debug(String message) {
        proxiedLogger.debug(message);
    }

    @Override
    public void debug(String message, Exception error) {
        proxiedLogger.debug(message, error);
    }

    @Override
    public void debugWithHexBlock(String message, byte[] data) {
        proxiedLogger.debugWithHexBlock(message, data);
    }

    @Override
    public void debugWithHexBlock(String message, byte[] data, int length) {
        proxiedLogger.debugWithHexBlock(message, data, length);
    }

    @Override
    public void debug(String message, byte[] data) {
        proxiedLogger.debug(message, data);
    }

    @Override
    public void warn(String message) {
        proxiedLogger.warn(message);
    }

    @Override
    public void info(String message) {
        proxiedLogger.info(message);
    }

    @Override
    public void info(String message, byte[] data) {
        proxiedLogger.info(message, data);
    }

    @Override
    public void received(Instant timeReceived, int datagram, QuicPacket packet) {
        proxiedLogger.received(timeReceived, datagram, packet);
    }

    @Override
    public void received(Instant timeReceived, int datagram, EncryptionLevel encryptionLevel, byte[] dcid, byte[] scid) {
        proxiedLogger.received(timeReceived, datagram, encryptionLevel, dcid, scid);
    }

    @Override
    public void sent(Instant sent, QuicPacket packet) {
        proxiedLogger.sent(sent, packet);
    }

    @Override
    public void sent(Instant sent, List<QuicPacket> packets) {
        proxiedLogger.sent(sent, packets);
    }

    @Override
    public void secret(String message, byte[] secret) {
        proxiedLogger.secret(message, secret);
    }

    @Override
    public void raw(String message, byte[] data) {
        proxiedLogger.raw(message, data);
    }

    @Override
    public void raw(String message, ByteBuffer data, int offset, int length) {
        proxiedLogger.raw(message, data, offset, length);
    }

    @Override
    public void raw(String message, byte[] data, int length) {
        proxiedLogger.raw(message, data, length);
    }

    @Override
    public void decrypted(String message, byte[] data) {
        proxiedLogger.decrypted(message, data);
    }

    @Override
    public void decrypted(String message, byte[] data, int length) {
        proxiedLogger.decrypted(message, data, length);
    }

    @Override
    public void decrypted(String message) {
        proxiedLogger.decrypted(message);
    }

    @Override
    public void encrypted(String message, byte[] data) {
        proxiedLogger.encrypted(message, data);
    }

    @Override
    public void error(String message) {
        proxiedLogger.error(message);
    }

    @Override
    public void error(String message, Throwable error) {
        proxiedLogger.error(message, error);
    }

    @Override
    public void stats(String message) {
        proxiedLogger.stats(message);
    }

    @Override
    public void recovery(String message) {
        proxiedLogger.recovery(message);
    }

    @Override
    public void recovery(String format, Instant lossTime) {
        proxiedLogger.recovery(format, lossTime);
    }

    @Override
    public void cc(String message) {
        proxiedLogger.cc(message);
    }

    @Override
    public void fc(String message) {
        proxiedLogger.fc(message);
    }

    @Override
    public void receivedPacketInfo(String info) {
        proxiedLogger.receivedPacketInfo(info);
    }

    @Override
    public void sentPacketInfo(String info) {
        proxiedLogger.sentPacketInfo(info);
    }

    @Override
    public QLog getQLog() {
        return qlogFrontEnd;
    }
}
