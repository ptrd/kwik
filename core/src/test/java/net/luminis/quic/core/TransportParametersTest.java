/*
 * Copyright © 2023, 2024 Peter Doornbosch
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
package net.luminis.quic.core;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


class TransportParametersTest {

    @Test
    void byDefaultParametersHaveDefaultValues() {
        TransportParameters transportParameters = new TransportParameters();
        assertThat(transportParameters.getAckDelayExponent()).isEqualTo(3);
        assertThat(transportParameters.getMaxAckDelay()).isEqualTo(25);

        // Except (!!!)
        assertThat(transportParameters.getMaxUdpPayloadSize()).isEqualTo(1500);
    }

    @Test
    void unspecifiedParametersHaveDefaultValues() {
        TransportParameters transportParameters = new TransportParameters(30_000, 250_000, 250_000, 250_000);
        assertThat(transportParameters.getAckDelayExponent()).isEqualTo(3);
        assertThat(transportParameters.getMaxAckDelay()).isEqualTo(25);

        // Except (!!!)
        assertThat(transportParameters.getMaxUdpPayloadSize()).isEqualTo(1500);
    }
}