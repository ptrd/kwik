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
package net.luminis.quic.log;

import net.luminis.quic.packet.QuicPacket;
import net.luminis.tls.ByteUtils;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;


public abstract class BaseLogger implements Logger {

    private volatile boolean logDebug = false;
    private volatile boolean logRawBytes = false;
    private volatile boolean logDecrypted = false;
    private volatile boolean logSecrets = false;
    private volatile boolean logPackets = false;
    private volatile boolean logInfo = false;
    private volatile boolean logWarning = false;
    private volatile boolean logStats = false;
    private volatile boolean logRecovery = false;
    private volatile boolean logCongestionControl = false;
    private volatile boolean logFlowControl = false;
    private volatile boolean useRelativeTime = false;
    private final DateTimeFormatter timeFormatter;
    private Instant start;


    public BaseLogger() {
        timeFormatter = DateTimeFormatter.ofPattern("mm:ss.SSS");
    }

    @Override
    public void logDebug(boolean enabled) {
        logDebug = enabled;
    }

    @Override
    public void logRaw(boolean enabled) {
        logRawBytes = enabled;
    }

    @Override
    public void logDecrypted(boolean enabled) {
        logDecrypted = enabled;
    }

    @Override
    public void logSecrets(boolean enabled) {
        logSecrets = enabled;
    }

    @Override
    public void logPackets(boolean enabled) {
        logPackets = enabled;
    }

    @Override
    public void logInfo(boolean enabled) {
        logInfo = enabled;
    }

    @Override
    public void logWarning(boolean enabled) {
        logWarning = enabled;
    }

    @Override
    public void logStats(boolean enabled) {
        logStats = enabled;
    }

    @Override
    public void logRecovery(boolean enabled) {
        logRecovery = enabled;
    }

    @Override
    public void logCongestionControl(boolean enabled) {
        logCongestionControl = enabled;
    }

    @Override
    public boolean logFlowControl() {
        return logFlowControl;
    }

    @Override
    public void logFlowControl(boolean enabled) {
        logFlowControl = enabled;
    }

    @Override
    public void useRelativeTime(boolean enabled) {
        useRelativeTime = enabled;
    }

    @Override
    public void debug(String message) {
        if (logDebug) {
            log(message);
        }
    }

    @Override
    public void debug(String message, Exception error) {
        if (logDebug) {
            log(message, error);
        }
    }

    @Override
    public void debugWithHexBlock(String message, byte[] data) {
        if (logDebug) {
            logWithHexDump(message + " (" + data.length + "): ", data, data.length);
        }
    }

    @Override
    public void debugWithHexBlock(String message, byte[] data, int length) {
        if (logDebug) {
            logWithHexDump(message + " (" + data.length + "): ", data, length);
        }
    }

    @Override
    public void debug(String message, byte[] data) {
        if (logDebug) {
            log(message + " (" + data.length + "): " + byteToHex(data));
        }
    }

    @Override
    public void warn(String message) {
        if (logWarning) {
            log(message);
        }
    }

    @Override
    public void info(String message) {
        if (logInfo) {
            log(message);
        }
    }

    @Override
    public void info(String message, byte[] data) {
        if (logInfo) {
            log(message + " (" + data.length + "): " + ByteUtils.bytesToHex(data));
        }
    }

    @Override
    public void received(Instant timeReceived, int datagram, QuicPacket packet) {
        if (logPackets) {
            log(formatTime(timeReceived) + " <- (" + datagram + ") " + packet);
        }
    }

    @Override
    public void receivedPacketInfo(String info) {
        if (logPackets) {
            int indent = formatTime(Instant.now()).length();
            log(" ".repeat(indent) + " -< " + info);
        }
    }

    @Override
    public void sent(Instant sent, QuicPacket packet) {
        synchronized (this) {
            if (useRelativeTime) {
                if (start == null) {
                    start = sent;
                }
            }
        }
        if (logPackets) {
            log(formatTime(sent) + " -> " + packet);
        }
    }

    @Override
    public void secret(String message, byte[] secret) {
        if (logSecrets) {
            log(message + ": " + byteToHex(secret));
        }
    }

    @Override
    public void raw(String message, byte[] data) {
        if (logRawBytes) {
            logWithHexDump(message + " (" + data.length + "): ", data, data.length);
        }
    }

    @Override
    public void raw(String message, ByteBuffer data, int offset, int length) {
        if (logRawBytes) {
            logWithHexDump(message + " (" + length + "): ", data, offset, length);
        }
    }

    @Override
    public void raw(String message, byte[] data, int length) {
        if (logRawBytes) {
            logWithHexDump(message + " (" + data.length + "): ", data, length);
        }
    }

    @Override
    public void decrypted(String message, byte[] data) {
        if (logDecrypted) {
            logWithHexDump(message + " (" + data.length + "): ", data, data.length);
        }
    }

    @Override
    public void decrypted(String message, byte[] data, int length) {
        if (logDecrypted) {
            logWithHexDump(message + " (" + data.length + "): ", data, length);
        }
    }

    @Override
    public void decrypted(String message) {
        if (logDecrypted) {
            log(message);
        }
    }

    @Override
    public void encrypted(String message, byte[] data) {
        // For debugging encryption/decryption code only.
    }

    @Override
    public void error(String message) {
        log("Error: " + message);
    }

    @Override
    public void error(String message, Throwable error) {
        log("Error: " + message + ": " + error, error);
    }

    @Override
    public void recovery(String message) {
        if (logRecovery) {
            log(formatTime(Instant.now()) + " " + message);
        }
    }

    @Override
    public void recovery(String message, Instant time) {
        if (logRecovery) {
            log(String.format(message, formatTime(time)));
        }
    }

    @Override
    public void cc(String message) {
        if (logCongestionControl) {
            log(formatTime(Instant.now()) + " " + message);
        }
    }

    @Override
    public void fc(String message) {
        if (logFlowControl) {
            log(formatTime(Instant.now()) + " " + message);
        }
    }

    @Override
    public void stats(String message) {
        if (logStats) {
            log(message);
        }
    }

    protected String byteToHex(byte[] data) {
        String result = "";
        for (int i = 0; i < data.length; i++) {
            result += (String.format("%02x ", data[i]));
        }
        return result;
    }

    protected String byteToHexBlock(byte[] data, int length) {
        String result = "";
        for (int i = 0; i < length; ) {
            result += (String.format("%02x ", data[i]));
            i++;
            if (i < data.length)
                if (i % 16 == 0)
                    result += "\n";
                else if (i % 8 == 0)
                    result += " ";
        }
        return result;
    }

    protected String byteToHexBlock(ByteBuffer data, int offset, int length) {
        data.rewind();
        String result = "";
        for (int i = 0; i < length; ) {
            result += String.format("%02x ", data.get(offset + i));
            i++;
            if (i < length)
                if (i % 16 == 0)
                    result += "\n";
                else if (i % 8 == 0)
                    result += " ";
        }
        return result;
    }

    protected String formatTime(Instant time) {
        if (useRelativeTime) {
            if (start == null) {
                start = time;
            }
            Duration relativeTime = Duration.between(start, time);
            return String.format("%.3f", ((double) relativeTime.toNanos()) / 1000000000);  // Use nano's to get correct rounding to millis
        }
        else {
            LocalTime localTimeNow = LocalTime.from(time.atZone(ZoneId.systemDefault()));
            return timeFormatter.format(localTimeNow);
        }
    }

    abstract protected void log(String message);

    abstract protected void log(String message, Throwable ex);

    abstract protected void logWithHexDump(String message, byte[] data, int length);

    abstract protected void logWithHexDump(String message, ByteBuffer data, int offset, int length);
}
