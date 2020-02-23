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
package net.luminis.quic;

import net.luminis.quic.log.Logger;
import net.luminis.tls.ByteUtils;
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
        params.parseTransportParameter(buffer, mock(Logger.class));

        TransportParameters.PreferredAddress preferredAddress = params.getTransportParameters().getPreferredAddress();

        assertThat(preferredAddress).isNotNull();
        assertThat(preferredAddress.ip4).isEqualTo(InetAddress.getByAddress(new byte[] { 4, 31, (byte) 198, 62 } ));
        assertThat(preferredAddress.ip4Port).isEqualTo(4433);
        assertThat(preferredAddress.ip6).isEqualTo(InetAddress.getByAddress(new byte[] { 0x20, 0x01, 0x18, (byte) 0x90, 0x12, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x2a }));
        assertThat(preferredAddress.ip6Port).isEqualTo(4433);
        assertThat(preferredAddress.connectionId).isEqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 });
        assertThat(preferredAddress.statelessResetToken).isEqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 });
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
        params.parseTransportParameter(buffer, mock(Logger.class));

        TransportParameters.PreferredAddress preferredAddress = params.getTransportParameters().getPreferredAddress();
        assertThat(preferredAddress.ip4).isNull();
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
        params.parseTransportParameter(buffer, mock(Logger.class));

        TransportParameters.PreferredAddress preferredAddress = params.getTransportParameters().getPreferredAddress();
        assertThat(preferredAddress.ip6).isNull();
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
                () -> params.parseTransportParameter(buffer, mock(Logger.class)))
                .isInstanceOf(ProtocolError.class);
    }

    @Test
    void testAckDelayTransportParameter() throws Exception {
        //                                                 id sz id sz
        byte[] rawData = ByteUtils.hexToBytes("ff a5 00 06 0a 01 07 0b 01 29".replaceAll(" ", ""));

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.IETF_draft_18);
        transportParametersExtension.parse(ByteBuffer.wrap(rawData), mock(Logger.class));

        assertThat(transportParametersExtension.getTransportParameters().getAckDelayExponent()).isEqualTo(7);
        assertThat(transportParametersExtension.getTransportParameters().getMaxAckDelay()).isEqualTo(41);
    }

    @Test
    void unknownTransportParameterShouldBeIgnored() throws Exception {
        //                                           ext size  unknown id     size dummy value       idle id sz value (0x40 | 27 10) (10000)
        byte[] rawData = ByteUtils.hexToBytes("ff a5 00 0e     80 00 ff f9      05 01 02 03 04 05    01      02 67 10".replaceAll(" ", ""));

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.IETF_draft_20);
        transportParametersExtension.parse(ByteBuffer.wrap(rawData), mock(Logger.class));

        assertThat(transportParametersExtension.getTransportParameters().getMaxIdleTimeout()).isEqualTo(10);
    }

    @Test
    void testParseMaxIdleTimeoutTransportParameter() throws Exception {
        //                                           ext size  id sz value 30.000 params size unknonw id size  dummy value    idle id size  0x40 | 27 10 (10000)
        byte[] rawData = ByteUtils.hexToBytes("ff a5 00 06     01 04 80 00 75 30".replaceAll(" ", ""));

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        transportParametersExtension.parse(ByteBuffer.wrap(rawData), mock(Logger.class));

        assertThat(transportParametersExtension.getTransportParameters().getMaxIdleTimeout()).isEqualTo(30);
    }

    @Test
    void testSerializeTransportParameters() throws Exception {
        TransportParameters tp = new TransportParameters(10, 1_048_576, 1024, 256);
        byte[] serializedForm = new QuicTransportParametersExtension(Version.getDefault(), tp).getBytes();

        QuicTransportParametersExtension transportParametersExtension = new QuicTransportParametersExtension(Version.getDefault());
        transportParametersExtension.parse(ByteBuffer.wrap(serializedForm), mock(Logger.class));

        assertThat(transportParametersExtension.getTransportParameters().getMaxIdleTimeout()).isEqualTo(10);
        assertThat(transportParametersExtension.getTransportParameters().getInitialMaxStreamDataBidiLocal()).isEqualTo(1_048_576);
        assertThat(transportParametersExtension.getTransportParameters().getInitialMaxStreamsBidi()).isEqualTo(1024);
        assertThat(transportParametersExtension.getTransportParameters().getInitialMaxStreamsUni()).isEqualTo(256);
    }
}
