package net.luminis.quic;

import net.luminis.tls.ByteUtils;
import net.luminis.tls.Extension;

import java.nio.ByteBuffer;

import static net.luminis.quic.QuicConstants.TransportParameterId.*;

// https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-18
public class QuicTransportParametersExtension extends Extension {

    private byte[] data;

    public QuicTransportParametersExtension() {
    }

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

        buffer.putShort(idle_timeout.value);
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

        buffer.putShort(initial_max_data.value);
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-18.1:
        // "The initial maximum data parameter contains the initial value for the maximum amount of data that can
        //  be sent on the connection.  This parameter is encoded as an unsigned 32-bit integer in units of octets."
        buffer.putShort((short) 4);
        buffer.putInt(1048576);

        buffer.putShort(initial_max_bidi_streams.value);
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

    // Assuming Handshake message type encrypted_extensions
    public void parse(ByteBuffer buffer, Logger log) {
        int extensionType = buffer.getShort() & 0xffff;
        if (extensionType != 0xffa5) {
            throw new RuntimeException();  // Must be programming error
        }

        int length = buffer.getShort();
        int negotiatedVersion = buffer.getInt();
        int supportedVersionsSize = buffer.get();
        for (int i = 0; i < supportedVersionsSize; i += 4) {
            int supportedVersion = buffer.getInt();
        }

        int transportParametersSize = buffer.getShort();
        log.debug("Transport parameters: ");
        while (buffer.remaining() > 0) {
            parseTransportParameter(buffer, log);
        }
    }

    void parseTransportParameter(ByteBuffer buffer, Logger log) {
        int parameterId = buffer.getShort();
        if (parameterId == initial_max_stream_data_bidi_local.value) {
            int size = buffer.getShort();
            int maxStreamDataBidiLocal = buffer.getInt();
            log.debug("- initial max stream data bidi local: " + maxStreamDataBidiLocal);
        }
        else if (parameterId == initial_max_data.value) {
            int size = buffer.getShort();
            int maxData = buffer.getInt();
            log.debug("- initial max data: " + maxData);
        }
        else if (parameterId == initial_max_bidi_streams.value) {
            int size = buffer.getShort();
            int maxBidiStreams = buffer.getShort();
            log.debug("- initial max bidi streams: " + maxBidiStreams);
        }
        else if (parameterId == idle_timeout.value) {
            int size = buffer.getShort();
            int idleTimeout = buffer.getShort();
            log.debug("- idle timeout: " + idleTimeout);
        }
        else if (parameterId == preferred_address.value) {
            throw new NotYetImplementedException();
        }
        else if (parameterId == max_packet_size.value) {
            int size = buffer.getShort();
            int maxPacketSize = buffer.getShort();
            log.debug("- max packet size: " + maxPacketSize);
        }
        else if (parameterId == stateless_reset_token.value) {
            int size = buffer.getShort();
            byte[] resetToken = new byte[16];
            buffer.get(resetToken);
            log.debug("- stateless reset token: " + ByteUtils.bytesToHex(resetToken));
        }
        else if (parameterId == ack_delay_exponent.value) {
            int size = buffer.getShort();
            int ackDelayExponent = buffer.get();
            log.debug("- ack delay exponent: " + ackDelayExponent);
        }
        else if (parameterId == initial_max_uni_streams.value) {
            int size = buffer.getShort();
            int maxUniStreams = buffer.getShort();
            log.debug("- max uni streams: " + maxUniStreams);
        }
        else if (parameterId == disable_migration.value) {
            int size = buffer.getShort();
            log.debug("- disable migration");
        }
        else if (parameterId == initial_max_stream_data_bidi_remote.value) {
            int size = buffer.getShort();
            int maxStreamDataBidiRemote = buffer.getInt();
            log.debug("- initial max stream data bidi remote: " + maxStreamDataBidiRemote);
        }
        else if (parameterId == initial_max_stream_data_uni.value) {
            int size = buffer.getShort();
            int maxStreamDataUni = buffer.getInt();
            log.debug("- initial max stream data uni: " + maxStreamDataUni);
        }
        else if (parameterId == max_ack_delay.value) {
            int size = buffer.getShort();
            int maxAckDelay = buffer.get();
            log.debug("- idle timeout: " + maxAckDelay);
        }
        else if (parameterId == original_connection_id.value) {
            throw new NotYetImplementedException();
        }
    }

}
