/*
 * Copyright © 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.tls;

import tech.kwik.core.test.ByteUtils;
import tech.kwik.agent15.ProtectionKeysType;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.engine.MessageProcessor;
import tech.kwik.agent15.engine.TlsMessageParser;
import tech.kwik.agent15.handshake.HandshakeMessage;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class ClientHelloBuilder {

    private List<String> extensionsAsHex = new ArrayList<>();

    public byte[] buildBinary() {
        //               ver random                                                          s cipher  c
        String coreCH = "030384b8e4012701f201be2008c144a89d30a63c2059400f3201e9390fe29a6ae26f00000213010100";
        //                          extension 00                            extension 2b  extension 0a    extension 0d    extension 33                                                                                                                                          extension 2d
        String defaultExtensions = "00000010000e00000b6578616d706c652e636f6d002b0003020304000a000400020017000d0004000208040033004700450017004104102e77433f7752be3e1ef8f29c6cb6d57d7685a5d7411336ef2157e70ee04c5b10772660368383749684507550e684e2e57ac431326cff6fcd8760383aac994a002d0003020001";
        String extensions = prefixWithLength(defaultExtensions + extensionsAsHex.stream().collect(Collectors.joining()));
        int chLength = coreCH.length() / 2 + extensions.length() / 2;
        String clientHelloHex = formatTypeAndLength("01", chLength) + coreCH + extensions;
        return ByteUtils.hexToBytes(clientHelloHex);
    }

    public ClientHelloBuilder withExtension(String extensionAsHex) {
        extensionsAsHex.add(extensionAsHex);
        return this;
    }

    private String prefixWithLength(String hex) {
        return String.format("%04x", hex.length() / 2) + hex;
    }

    private String formatTypeAndLength(String type, int length) {
        return type + String.format("%06x", length);
    }

    @Test
    void testValidClientHello() throws Exception {
        // When
        HandshakeMessage handshakeMessage = new TlsMessageParser().parseAndProcessHandshakeMessage(ByteBuffer.wrap(this.buildBinary()), mock(MessageProcessor.class), ProtectionKeysType.None);

        // Then
        assertThat(handshakeMessage.getType()).isEqualTo(TlsConstants.HandshakeType.client_hello);
    }
}
