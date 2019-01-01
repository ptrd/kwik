package net.luminis.quic;

import java.nio.ByteBuffer;

public class Logger {

    private boolean logDebug = false;
    private boolean logRawBytes = false;
    private boolean logDecrypted = false;
    private boolean logSecrets = false;
    private boolean logPackets = false;
    private boolean logInfo = false;

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

    public void debug(String message) {
        if (logDebug) {
            System.out.println(message);
        }
    }

    public void debugWithHexBlock(String message, byte[] data) {
        if (logDebug) {
            System.out.println(message + " (" + data.length + "): ");
            System.out.println(byteToHexBlock(data, data.length));
        }
    }

    public void debugWithHexBlock(String message, byte[] data, int length) {
        if (logDebug) {
            System.out.println(message + " (" + length + "): ");
            System.out.println(byteToHexBlock(data, length));
        }
    }

    public void debug(String message, byte[] data) {
        if (logDebug) {
            System.out.println(message + " (" + data.length + "): " + byteToHex(data));
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
            System.out.println(message);
        }
    }

    public void info(String message, byte[] data) {
        if (logInfo) {
            System.out.println(message + " (" + data.length + "): ");
            System.out.println(byteToHexBlock(data, data.length));
        }
    }

    public void received(QuicPacket packet) {
        if (logPackets) {
            System.out.println("<< " + packet);
        }
    }

    public void sent(QuicPacket packet) {
        if (logPackets) {
            System.out.println(">> " + packet);
        }
    }

    public void secret(String message, byte[] secret) {
        if (logSecrets) {
            System.out.println(message + ": " + byteToHex(secret));
        }
    }

    public void raw(String message, byte[] data) {
        if (logRawBytes) {
            System.out.println(message + " (" + data.length + "): ");
            System.out.println(byteToHexBlock(data, data.length));
        }
    }

    public void raw(String message, ByteBuffer data, int offset, int length) {
        if (logRawBytes) {
            System.out.println(message + " (" + length + "): ");
            System.out.println(byteToHexBlock(data, offset, length));
        }
    }

    public void raw(String message, byte[] data, int length) {
        if (logRawBytes) {
            System.out.println(message + " (" + data.length + "): ");
            System.out.println(byteToHexBlock(data, length));
        }
    }

    public void decrypted(String message, byte[] data) {
        if (logDecrypted) {
            System.out.println(message + " (" + data.length + "): ");
            System.out.println(byteToHexBlock(data, data.length));
        }
    }

    public void decrypted(String message, byte[] data, int length) {
        if (logDecrypted) {
            System.out.println(message + " (" + data.length + "): ");
            System.out.println(byteToHexBlock(data, length));
        }
    }

    public void decrypted(String message) {
        if (logDecrypted) {
            System.out.println(message);
        }
    }

    public void error(String message) {
        System.out.println("Error: " + message);
    }
}
