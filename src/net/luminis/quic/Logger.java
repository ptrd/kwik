package net.luminis.quic;

public class Logger {

    public void debug(String message) {
        System.out.println(message);
    }

    public void debugWithHexBlock(String message, byte[] data) {
        System.out.println(message + " (" + data.length + "): ");
        System.out.println(byteToHexBlock(data, data.length));
    }

    public void debugWithHexBlock(String message, byte[] data, int length) {
        System.out.println(message + " (" + length + "): ");
        System.out.println(byteToHexBlock(data, length));
    }

    public void debug(String message, byte[] data) {
        System.out.println(message + " (" + data.length + "): " + byteToHex(data));
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

    public void info(String message) {
        System.out.println(message);
    }

    public void received(QuicPacket packet) {
        System.out.println("<< " + packet);
    }

    public void sent(QuicPacket packet) {
        System.out.println(">> " + packet);
    }
}
