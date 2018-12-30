package net.luminis.quic;

import net.luminis.tls.Extension;

public class ECPointFormatExtension extends Extension {

    @Override
    public byte[] getBytes() {
        return new byte[] {
                (byte) 0x00, (byte) 0x0b, (byte) 0x00, (byte) 0x04, (byte) 0x03, (byte) 0x00, (byte) 0x01, (byte) 0x02
        };
    }
}
