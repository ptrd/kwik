package net.luminis.quic;

public class QuicConstants {

    // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-18

    public enum TransportParameterId {
        initial_max_stream_data_bidi_local(0),
        initial_max_data(1),
        initial_max_bidi_streams(2),
        idle_timeout(3),
        preferred_address(4),
        max_packet_size(5),
        stateless_reset_token(6),
        ack_delay_exponent(7),
        initial_max_uni_streams(8),
        disable_migration(9),
        initial_max_stream_data_bidi_remote(10),
        initial_max_stream_data_uni(11),
        max_ack_delay(12),
        original_connection_id(13),
        // (65535)
        ;
        public final short value;

        TransportParameterId(int value) {
            this.value = (short) value;
        }
    };

}
