/*
 * Copyright © 2021 Peter Doornbosch
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

import java.util.ArrayList;
import java.util.List;


import static org.assertj.core.api.Assertions.assertThat;


class RangeTest {

    @Test
    void sizeShouldReturnCountOfNumbersInRange() {
        var range = new Range(3L, 7L);

        assertThat(range.size()).isEqualTo(5);
    }

    @Test
    void testGetters() {
        var range = new Range(3L, 7L);

        assertThat(range.getLargest()).isEqualTo(7);
        assertThat(range.getSmallest()).isEqualTo(3);
    }

    @Test
    void streamShouldListAllNumbersInRange() {
         var range = new Range(3L, 7L);

         assertThat(range.stream().toArray()).isEqualTo(new Long[] { 7L, 6L, 5L, 4L, 3L });
    }

    @Test
    void extendEmptyRangeList() {
        var rangeList = createRangeList();

        Range.extendRangeList(rangeList, 3L);

        assertThat(rangeList).containsExactly(new Range(3L, 3L));
    }

    @Test
    void extendRangeWithLargerNumber() {
        var rangeList = createRangeList();

        Range.extendRangeList(rangeList, 3L);
        Range.extendRangeList(rangeList, 4L);

        assertThat(rangeList).containsExactly(new Range(3L, 4L));
    }

    @Test
    void extendRangeWithSmallerNumber() {
        var rangeList = createRangeList();

        Range.extendRangeList(rangeList, 3L);
        Range.extendRangeList(rangeList, 2L);

        assertThat(rangeList).containsExactly(new Range(2L, 3L));
    }

    @Test
    void extendRangeListWithExistingNumber() {
        var rangeList = createRangeList(new Range(21L, 27L), new Range(15L, 16L), new Range(7L, 9L));

        Range.extendRangeList(rangeList, 25L);


        assertThat(rangeList).containsExactly(new Range(21L, 27L), new Range(15L, 16L), new Range(7L, 9L));
    }

    @Test
    void extendRangeListWithRange() {
        var rangeList = createRangeList(new Range(21L, 27L), new Range(15L, 16L), new Range(7L, 9L));

        Range.extendRangeList(rangeList, 19L);

        assertThat(rangeList).containsExactly(new Range(21L, 27L), new Range(19L, 19L), new Range(15L, 16L), new Range(7L, 9L));
    }

    @Test
    void appendRangeListWithRange() {
        var rangeList = createRangeList(new Range(21L, 27L), new Range(15L, 16L), new Range(7L, 9L));

        Range.extendRangeList(rangeList, 4L);

        assertThat(rangeList).containsExactly(new Range(21L, 27L), new Range(15L, 16L), new Range(7L, 9L), new Range(4L));
    }

    @Test
    void rangesThatBecomeAdjacentShouldBeCompacted() {
        var rangeList = createRangeList(new Range(21L, 27L), new Range(15L, 19L));

        Range.extendRangeList(rangeList, 20L);

        assertThat(rangeList).containsExactly(new Range(15L, 27L));
    }

    @Test
    void testRangeSubtract1() {
        //  ----
        // ----
        assertThat(range(5, 11).subtract(range(3, 6))).isEqualTo(range(7, 11));
    }

    @Test
    void testRangeSubtract2() {
        // -----
        // ----
        assertThat(range(5, 11).subtract(range(5, 6))).isEqualTo(range(7, 11));
    }

    @Test
    void testRangeSubtract3() {
        // ----
        //   --
        assertThat(range(5, 11).subtract(range(8, 11))).isEqualTo(range(5, 7));
    }

    @Test
    void testRangeSubtract4() {
        // -----
        //   -----
        assertThat(range(5, 8).subtract(range(6, 10))).isEqualTo(range(5, 5));
    }

    private List<Range> createRangeList(Range... ranges) {
        var rangeList = new ArrayList<Range>();
        for (Range range: ranges) {
            rangeList.add(range);
        }
        return rangeList;
    }

    Range range(int from, int to) {
        return new Range(from, to);
    }

    Range range(int single) {
        return new Range(single, single);
    }
}