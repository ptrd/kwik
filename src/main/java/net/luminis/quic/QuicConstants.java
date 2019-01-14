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
