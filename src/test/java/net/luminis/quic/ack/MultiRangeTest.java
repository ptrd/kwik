/*
 * Copyright © 2022 Peter Doornbosch
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
package net.luminis.quic.ack;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


class MultiRangeTest {

    @Test
    void streamShouldListAllNumbersInRanges() {
         var multiRange = new MultiRange(new Range(3L, 7L), new Range(10, 13));

         assertThat(multiRange.stream().toArray()).isEqualTo(new Long[] { 13L, 12L, 11L, 10L, 7L, 6L, 5L, 4L, 3L });
    }

    @Test
    void streamEmptyRangeShouldListNothing() {
        assertThat(MultiRange.empty().stream().toArray()).isEqualTo(new Long[0]);
    }
}