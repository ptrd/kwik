package net.luminis.quic;

import net.luminis.tls.Extension;

import java.nio.ByteBuffer;

// https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-18
public class QuicTransportParametersExtension extends Extension {

    private final byte[] data;

    /**
     * Creates a Quic Transport Parameters Extension for use in a Client Hello.
     * @param quicVersion
     */
    public QuicTransportParametersExtension(Version quicVersion) {
        ByteBuffer buffer = ByteBuffer.allocate(1500);

        // https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-8.2:
        // "quic_transport_parameters(0xffa5)"
        buffer.putShort((short) 0xffa5);

        // Format is same as any TLS extension, so next are 2 bytes length
        buffer.putShort((short) 0);  // PlaceHolder, will be correctly set at the end of this method.

        // For use in Client Hello: just the initial quic version
        buffer.put(quicVersion.getBytes());

        // Length of transport parameters vector: use placeholder.
        int transportParametersLengthPosition = buffer.position();
        buffer.putShort((short) 0);

        buffer.putShort(QuicConstants.TransportParameterId.idle_timeout.value);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-18.1:
        // "The idle timeout is a value in seconds that is encoded as an unsigned 16-bit integer."
        buffer.putShort((short) 2);
        buffer.putShort((short) 30);

        buffer.putShort(QuicConstants.TransportParameterId.initial_max_stream_data_bidi_local.value);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-18.1:
        // "Either peer MAY advertise an initial value for flow control of each type of stream on which they might receive data.
        // Each of the following transport parameters is encoded as an unsigned 32-bit integer in units of octets: ..."
        buffer.putShort((short) 4);
        buffer.putInt(262144);

        buffer.putShort(QuicConstants.TransportParameterId.initial_max_stream_data_bidi_remote.value);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-18.1:
        // "Either peer MAY advertise an initial value for flow control of each type of stream on which they might receive data.
        // Each of the following transport parameters is encoded as an unsigned 32-bit integer in units of octets: ..."
        buffer.putShort((short) 4);
        buffer.putInt(262144);

        buffer.putShort(QuicConstants.TransportParameterId.initial_max_stream_data_uni.value);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-18.1:
        // "Either peer MAY advertise an initial value for flow control of each type of stream on which they might receive data.
        // Each of the following transport parameters is encoded as an unsigned 32-bit integer in units of octets: ..."
        buffer.putShort((short) 4);
        buffer.putInt(262144);

        buffer.putShort(QuicConstants.TransportParameterId.initial_max_data.value);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-18.1:
        // "The initial maximum data parameter contains the initial value for the maximum amount of data that can
        //  be sent on the connection.  This parameter is encoded as an unsigned 32-bit integer in units of octets."
        buffer.putShort((short) 4);
        buffer.putInt(1048576);

        buffer.putShort(QuicConstants.TransportParameterId.initial_max_bidi_streams.value);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-18.1:
        // "The initial maximum bidirectional streams parameter contains the initial maximum number of
        //  bidirectional streams the peer may initiate, encoded as an unsigned 16-bit integer."
        buffer.putShort((short) 2);
        buffer.putShort((short) 1);

        buffer.putShort(QuicConstants.TransportParameterId.initial_max_uni_streams.value);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-18.1:
        // "The initial maximum unidirectional streams parameter contains the initial maximum number of
        //  unidirectional streams the peer may initiate, encoded as an unsigned 16-bit integer."
        buffer.putShort((short) 2);
        buffer.putShort((short) 1);

        int length = buffer.position();
        buffer.limit(length);

        int transportParametersSize = length - transportParametersLengthPosition - 2;  // 2 bytes for the size itself
        buffer.putShort(transportParametersLengthPosition, (short) transportParametersSize);

        int extensionsSize = length - 2 - 2;  // 2 bytes for the length itself and 2 for the type
        buffer.putShort(2, (short) extensionsSize);

        data = new byte[length];
        buffer.flip();
        buffer.get(data);
    }

    @Override
    public byte[] getBytes() {
        return data;
    }
}
