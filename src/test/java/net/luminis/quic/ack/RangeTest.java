package net.luminis.quic.ack;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;


import static org.assertj.core.api.Assertions.assertThat;


class RangeTest {

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

    private List<Range> createRangeList(Range... ranges) {
        var rangeList = new ArrayList<Range>();
        for (Range range: ranges) {
            rangeList.add(range);
        }
        return rangeList;
    }
}