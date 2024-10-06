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
package net.luminis.quic.tls;

import net.luminis.quic.impl.ProtocolError;
import net.luminis.quic.impl.Role;
import net.luminis.quic.impl.TransportParameters;
import net.luminis.quic.impl.Version;
import net.luminis.quic.log.Logger;
import net.luminis.quic.test.ByteUtils;
import net.luminis.tls.alert.DecodeErrorException;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;


class QuicTransportParametersExtensionTest {

    @Test
    void parsePreferredAddressTransportParameter() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[] {
                // id size  ip4..................  port
                0x0d, 0x39, 4, 31, (byte) 198, 62, 0x11, 0x51,
                // ip6   2001:1890:126c:0:0:0:1:2a
                0x20, 0x01, 0x18, (byte) 0x90, 0x12, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x2a,
                // port     length      // connection id
                0x11, 0x51, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                // stateless reset token
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
        });

        QuicTransportParametersExtension params = new QuicTransportParametersExtension();
        params.parseTransportParameter(buffer, Role.Server, mock(Logger.class));

        TransportParameters.PreferredAddress preferredAddress = params.getTransportParameters().getPreferredAddress();

        assertThat(preferredAddress).isNotNull();
        assertThat(preferredAddress.getIp4()).isEqualTo(InetAddress.getByAddress(new byte[] { 4, 31, (byte) 198, 62 } ));
        assertThat(preferredAddress.getIp4Port()).isEqualTo(4433);
        assertThat(preferredAddress.getIp6()).isEqualTo(InetAddress.getByAddress(new byte[] { 0x20, 0x01, 0x18, (byte) 0x90, 0x12, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x2a }));
        assertThat(preferredAddress.getIp6Port()).isEqualTo(4433);
        assertThat(preferredAddress.getConnectionId()).isEqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 });
        assertThat(preferredAddress.getStatelessResetToken()).isEqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 });
    }

    @Test
    void parsePreferredAddressTransportParameterDetectsZeroIP4() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[] {
                // id size  ip4.......  port
                0x0d, 0x39, 0, 0, 0, 0, 0, 0,
                // ip6   2001:1890:126c:0:0:0:1:2a
                0x20, 0x01, 0x18, (byte) 0x90, 0x12, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x2a,
                // port     length      // connection id
                0x11, 0x51, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                // stateless reset token
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
        });

        QuicTransportParametersExtension params = new QuicTransportParametersExtension();
        params.parseTransportParameter(buffer, Role.Server, mock(Logger.class));

        TransportParameters.PreferredAddress preferredAddress = params.getTransportParameters().getPreferredAddress();
        assertThat(preferredAddress.getIp4()).isNull();
    }

    @Test
    void parsePreferredAddressTransportParameterDetectsZeroIP6() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[] {
                // id size     ip4..................     port
                0x0d, 0x39, 4, 31, (byte) 198, 62, 0x11, 0x51,
                // ip6   0:0:0:0:0:0:0:0
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                // port   length      // connection id
                0, 0,     0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                // stateless reset token
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
        });

        QuicTransportParametersExtension params = new QuicTransportParametersExtension();
        params.parseTransportParameter(buffer, Role.Server, mock(Logger.class));

        TransportParameters.PreferredAddress preferredAddress = params.getTransportParameters().getPreferredAddress();
        assertThat(preferredAddress.getIp6()).isNull();
    }

    @Test
    void parsePreferredAddressTransportParameterChecksForIP4OrIP6() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[]{
                // id size  ip4.......  port
                0x0d, 0x39, 0, 0, 0, 0, 0, 0,
                // ip6   0:0:0:0:0:0:0:0
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                // port     length      // connection id
                0x11, 0x51, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                // stateless reset token
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
        });

        QuicTransportParametersExtension params = new QuicTransportParametersExtension();

        assertThatThrownBy(
                () -> params.parseTransportParameter(buffer, Role.Server, mock(Logger.class)))
                .isInstanceOf(ProtocolError.class);
    }

    @Test
    void testAckDelayTransportParameter() throws Exception {
        //                                                 id sz id sz
        byte[] rawData = ByteUtils.hexToBytes("00 39 00 06 0a 01 07 0b 01 29".replaceAll(" ", ""));

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        transportParametersExtension.parse(ByteBuffer.wrap(rawData), Role.Server, mock(Logger.class));

        assertThat(transportParametersExtension.getTransportParameters().getAckDelayExponent()).isEqualTo(7);
        assertThat(transportParametersExtension.getTransportParameters().getMaxAckDelay()).isEqualTo(41);
    }

    @Test
    void unknownTransportParameterShouldBeIgnored() throws Exception {
        //                                           ext size  unknown id     size dummy value       idle id sz value (0x40 | 27 10) (10000)
        byte[] rawData = ByteUtils.hexToBytes("00 39 00 0e     80 00 ff f9      05 01 02 03 04 05    01      02 67 10".replaceAll(" ", ""));

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        transportParametersExtension.parse(ByteBuffer.wrap(rawData), Role.Server, mock(Logger.class));

        assertThat(transportParametersExtension.getTransportParameters().getMaxIdleTimeout()).isEqualTo(10_000);
    }

    @Test
    void testParseMaxIdleTimeoutTransportParameter() throws Exception {
        //                                           ext size  id sz value 30.000 params size unknonw id size  dummy value    idle id size  0x40 | 27 10 (10000)
        byte[] rawData = ByteUtils.hexToBytes("00 39 00 06     01 04 80 00 75 30".replaceAll(" ", ""));

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        transportParametersExtension.parse(ByteBuffer.wrap(rawData), Role.Server, mock(Logger.class));

        assertThat(transportParametersExtension.getTransportParameters().getMaxIdleTimeout()).isEqualTo(30_000);
    }

    @Test
    void testSerializeTransportParameters() throws Exception {
        TransportParameters tp = new TransportParameters(10, 1_048_576, 1024, 256);
        tp.setInitialSourceConnectionId(new byte[] { 0x01, 0x02, 0x03, 0x04 });
        byte[] serializedForm = new QuicTransportParametersExtension(Version.getDefault(), tp, Role.Client).getBytes();

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        transportParametersExtension.parse(ByteBuffer.wrap(serializedForm), Role.Server, mock(Logger.class));

        assertThat(transportParametersExtension.getTransportParameters().getMaxIdleTimeout()).isEqualTo(10_000);
        assertThat(transportParametersExtension.getTransportParameters().getInitialMaxStreamDataBidiLocal()).isEqualTo(1_048_576);
        assertThat(transportParametersExtension.getTransportParameters().getInitialMaxStreamsBidi()).isEqualTo(1024);
        assertThat(transportParametersExtension.getTransportParameters().getInitialMaxStreamsUni()).isEqualTo(256);
    }

    @Test
    void parseInitialSourceCconnectionId() throws Exception {
        //                                                 id sz
        byte[] rawData = ByteUtils.hexToBytes("00 39 00 0a 0f 08 01 02 03 04 05 06 07 08".replaceAll(" ", ""));

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        transportParametersExtension.parse(ByteBuffer.wrap(rawData), Role.Server, mock(Logger.class));

        assertThat(transportParametersExtension.getTransportParameters().getInitialSourceConnectionId()).isEqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
    }

    @Test
    void serializeWithEmptySourceConnectionId() throws Exception {
        TransportParameters tp = new TransportParameters(10, 1_048_576, 1024, 256);
        tp.setInitialSourceConnectionId(new byte[0]);

        byte[] serializedForm = new QuicTransportParametersExtension(Version.getDefault(), tp, Role.Client).getBytes();

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        transportParametersExtension.parse(ByteBuffer.wrap(serializedForm), Role.Server, mock(Logger.class));
        assertThat(transportParametersExtension.getTransportParameters().getInitialSourceConnectionId()).isEqualTo(new byte[0]);
    }

    @Test
    void parseRetrySourceConnectionId() throws Exception {
        //                                                 id sz
        byte[] rawData = ByteUtils.hexToBytes("00 39 00 0a 10 08 01 02 03 04 05 06 07 08".replaceAll(" ", ""));

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        transportParametersExtension.parse(ByteBuffer.wrap(rawData), Role.Server, mock(Logger.class));

        assertThat(transportParametersExtension.getTransportParameters().getRetrySourceConnectionId()).isEqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
    }

    @Test
    void parseTransportParametersExtensionFromLargerBuffer() throws Exception {
        //                                                 id sz
        byte[] rawData = ByteUtils.hexToBytes("00 39 00 0a 0f 08 01 02 03 04 05 06 07 08 01 02 03".replaceAll(" ", ""));

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        transportParametersExtension.parse(ByteBuffer.wrap(rawData), Role.Server, mock(Logger.class));
    }

    @Test
    void parseTooShortTransportParametersExtension() throws Exception {
        //                                                 id sz
        byte[] rawData = ByteUtils.hexToBytes("00 39 00 0a 0f 08 01".replaceAll(" ", ""));

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        assertThatThrownBy(() ->
                transportParametersExtension.parse(ByteBuffer.wrap(rawData), Role.Server, mock(Logger.class)))
                .isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseTransportParameterWithCorruptLength() throws Exception {
        //                                                 id sz
        byte[] rawData = ByteUtils.hexToBytes("00 39 00 03 08 41".replaceAll(" ", ""));

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        assertThatThrownBy(() ->
                transportParametersExtension.parse(ByteBuffer.wrap(rawData), Role.Server, mock(Logger.class)))
                .isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseTransportParameterWithInconsistentSize() throws Exception {
        //                                                 id sz
        byte[] rawData = ByteUtils.hexToBytes("00 39 00 03 08 02 03 ff".replaceAll(" ", ""));

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        assertThatThrownBy(() ->
                transportParametersExtension.parse(ByteBuffer.wrap(rawData), Role.Server, mock(Logger.class)))
                .isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseTruncatedVersionInformation() {
        //                                                 id sz
        byte[] rawData = ByteUtils.hexToBytes("00 39 00 0c 11 0a 00 00 00 01 70 9a 50 c4 00 00");
        var transportParametersExtension = new QuicTransportParametersExtension(Version.QUIC_version_1);
        assertThatThrownBy(() ->
                transportParametersExtension.parse(ByteBuffer.wrap(rawData), Role.Server, mock(Logger.class)))
                .isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseValidVersionInformation() throws Exception {
        //                                                 id sz
        byte[] rawData = ByteUtils.hexToBytes("00 39 00 0e 11 0c 00 00 00 01 6b 33 43 cf 00 00 00 01");
        var transportParametersExtension = new QuicTransportParametersExtension(Version.QUIC_version_1);
        transportParametersExtension.parse(ByteBuffer.wrap(rawData), Role.Client, mock(Logger.class));
        var versionInfo = transportParametersExtension.getTransportParameters().getVersionInformation();
        assertThat(versionInfo).isNotNull();
        assertThat(versionInfo.getChosenVersion()).isEqualTo(Version.QUIC_version_1);
        assertThat(versionInfo.getOtherVersions()).containsExactly(Version.QUIC_version_2, Version.QUIC_version_1);
    }

    @Test
    void parseMaxDatagramFrameSize() throws Exception {
        //                                           ext size  id sz value
        byte[] rawData = ByteUtils.hexToBytes("00 39 00 04     20 02 45 dc".replaceAll(" ", ""));
        var transportParametersExtension = new QuicTransportParametersExtension(Version.QUIC_version_1);
        transportParametersExtension.parse(ByteBuffer.wrap(rawData), Role.Client, mock(Logger.class));
        assertThat(transportParametersExtension.getTransportParameters().getMaxDatagramFrameSize()).isEqualTo(1500);
    }
}
