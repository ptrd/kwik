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

public class Logger {

    private volatile boolean logDebug = false;
    private volatile boolean logRawBytes = false;
    private volatile boolean logDecrypted = false;
    private volatile boolean logSecrets = false;
    private volatile boolean logPackets = false;
    private volatile boolean logInfo = false;
    private volatile boolean logStats = false;

    public void logDebug(boolean enabled) {
        logDebug = enabled;
    }

    public void logRaw(boolean enabled) {
        logRawBytes = enabled;
    }

    public void logDecrypted(boolean enabled) {
        logDecrypted = enabled;
    }

    public void logSecrets(boolean enabled) {
        logSecrets = enabled;
    }

    public void logPackets(boolean enabled) {
        logPackets = enabled;
    }

    public void logInfo(boolean enabeled) {
        logInfo = enabeled;
    }

    public void logStats(boolean enabeled) {
        logStats = enabeled;
    }

    public void debug(String message) {
        if (logDebug) {
            synchronized (this) {
                System.out.println(message);
            }
        }
    }

    public void debugWithHexBlock(String message, byte[] data) {
        if (logDebug) {
            synchronized (this) {
                System.out.println(message + " (" + data.length + "): ");
                System.out.println(byteToHexBlock(data, data.length));
            }
        }
    }

    public void debugWithHexBlock(String message, byte[] data, int length) {
        if (logDebug) {
            synchronized (this) {
                System.out.println(message + " (" + length + "): ");
                System.out.println(byteToHexBlock(data, length));
            }
        }
    }

    public void debug(String message, byte[] data) {
        if (logDebug) {
            synchronized (this) {
                System.out.println(message + " (" + data.length + "): " + byteToHex(data));
            }
        }
    }

    private String byteToHex(byte[] data) {
        String result = "";
        for (int i = 0; i < data.length; i++) {
            result += (String.format("%02x ", data[i]));
        }
        return result;
    }

    private String byteToHexBlock(byte[] data, int length) {
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

    private String byteToHexBlock(ByteBuffer data, int offset, int length) {
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

    public void info(String message) {
        if (logInfo) {
            synchronized (this) {
                System.out.println(message);
            }
        }
    }

    public void info(String message, byte[] data) {
        if (logInfo) {
            synchronized (this) {
                System.out.println(message + " (" + data.length + "): ");
                System.out.println(byteToHexBlock(data, data.length));
            }
        }
    }

    public void received(QuicPacket packet) {
        if (logPackets) {
            synchronized (this) {
                System.out.println("<< " + packet);
            }
        }
    }

    public void sent(QuicPacket packet) {
        if (logPackets) {
            synchronized (this) {
                System.out.println(">> " + packet);
            }
        }
    }

    public void secret(String message, byte[] secret) {
        if (logSecrets) {
            synchronized (this) {
                System.out.println(message + ": " + byteToHex(secret));
            }
        }
    }

    public void raw(String message, byte[] data) {
        if (logRawBytes) {
            synchronized (this) {
                System.out.println(message + " (" + data.length + "): ");
                System.out.println(byteToHexBlock(data, data.length));
            }
        }
    }

    public void raw(String message, ByteBuffer data, int offset, int length) {
        if (logRawBytes) {
            synchronized (this) {
                System.out.println(message + " (" + length + "): ");
                System.out.println(byteToHexBlock(data, offset, length));
            }
        }
    }

    public void raw(String message, byte[] data, int length) {
        if (logRawBytes) {
            synchronized (this) {
                System.out.println(message + " (" + data.length + "): ");
                System.out.println(byteToHexBlock(data, length));
            }
        }
    }

    public void decrypted(String message, byte[] data) {
        if (logDecrypted) {
            synchronized (this) {
                System.out.println(message + " (" + data.length + "): ");
                System.out.println(byteToHexBlock(data, data.length));
            }
        }
    }

    public void decrypted(String message, byte[] data, int length) {
        if (logDecrypted) {
            synchronized (this) {
                System.out.println(message + " (" + data.length + "): ");
                System.out.println(byteToHexBlock(data, length));
            }
        }
    }

    public void decrypted(String message) {
        if (logDecrypted) {
            synchronized (this) {
                System.out.println(message);
            }
        }
    }

    public void error(String message) {
        synchronized (this) {
            System.out.println("Error: " + message);
        }
    }

    public void stats(String message) {
        if (logStats) {
            synchronized (this) {
                System.out.println(message);
            }
        }
    }
}
