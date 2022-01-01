/*
 * Copyright © 2021, 2022 Peter Doornbosch
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

import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * Immutable range, identified by a "from" and a "to" field, both are inclusive (part of the range).
 */
public class Range {

    private final long from;
    private final long to;

    public Range(long from, long to) {
        if (from > to) {
            throw new IllegalArgumentException();
        }
        this.from = from;
        this.to = to;
    }

    public Range(long fromTo) {
        this.from = fromTo;
        this.to = fromTo;
    }

    public Range(int from, int to) {
        this((long) from, (long) to);
    }

    /**
     * Checks whether the range list is valid, i.e. ranges are not overlapping or adjacent and are sorted largest to
     * smallest.
     * @param ackRanges
     * @return
     */
    public static boolean validRangeList(List<Range> ackRanges) {
        Iterator<Range> iterator = ackRanges.iterator();
        long previousSmallest = Long.MAX_VALUE;
        while (iterator.hasNext()) {
            Range next = iterator.next();
            if (next.to >= previousSmallest - 1) {
                return false;
            }
            previousSmallest = next.from;
        }
        return true;
    }

    public boolean canBeExtendedWith(long number) {
        return number == from - 1 || number == to + 1;
    }

    public boolean contains(long number) {
        return number >= from && number <= to;
    }

    public Range extendWith(long number) {
        if (number == to + 1) {
            return new Range(from, to + 1);
        }
        else if (number == from - 1) {
            return new Range(from - 1, to);
        }
        else {
             throw new IllegalArgumentException("Range cannot be extended with that number " + number);
        }
    }

    public Range extendWith(long number, Range next) {
        if (number == next.to + 1 && from - 1 == number) {
            return new Range(next.from, to);
        }
        else if (to + 1 == number && number == next.from - 1) {
            return new Range(from, next.to);
        }
        else {
            throw new IllegalArgumentException();
        }
    }

    public Range subtract(Range other) {
        assert ! this.equals(other);
        if (this.equals(other)) {
            // Subtraction would lead to empty range
            throw new IllegalArgumentException();
        }
        assert ! this.properlyContains(other);
        if (this.properlyContains(other)) {
            // Subtraction would lead to two ranges
            throw new IllegalArgumentException();
        }
        assert ! other.properlyContains(this);
        if (other.properlyContains(this)) {
            // Subtraction would lead to empty range
            throw new IllegalArgumentException();
        }

        if (this.from > other.to || this.to < other.from) {
            return this;
        }
        // this  -------
        // other   -----
        if (this.from < other.from && this.to == other.to) {
            return new Range(from, other.from - 1);
        }
        // this    -----
        // other -----
        if (this.from > other.from && this.to > other.to) {
            return new Range(other.to + 1, this.to);
        }
        // this   -----
        // other  ---
        if (this.from == other.from && this.to > other.to) {
            return new Range(other.to + 1, this.to);
        }
        // this  -----
        // other   -----
        if (this.from < other.from && this.to < other.to) {
            return new Range(this.from, other.from - 1);
        }
        throw new IllegalStateException();
    }

    /**
     * Extends a range list with a given number; if the number is adjacent to an existing range, the range is extended,
     * otherwise a new range is inserted in the right position, keeping the list sorted.
     * Invariant (pre- and post-condition): list is sorted from largest range to smallest and ranges do not overlap and
     * are not adjacent.
     * @param ranges
     * @param number
     * @return  true is the range list is changed, i.e. when a range is extended or a new range is added.
     */
    public static boolean extendRangeList(List<Range> ranges, long number) {
        int index = 0;
        Iterator<Range> iterator = ranges.iterator();
        while (iterator.hasNext()) {
            Range current = iterator.next();
            if (current.contains(number)) {
                return false;
            }
            else if (current.canBeExtendedWith(number)) {
                Range next = null;
                if (iterator.hasNext()) {
                    next = iterator.next();
                }
                if (next != null && next.canBeExtendedWith(number)) {
                    ranges.set(index, ranges.get(index).extendWith(number, next));
                    ranges.remove(index + 1);
                    return true;
                }
                else {
                    ranges.set(index, ranges.get(index).extendWith(number));
                }
                return true;
            }
            else if (current.to < number) {
                ranges.add(index, new Range(number));
                return true;
            }
            index++;
        }
        ranges.add(index, new Range(number));
        return true;
    }

    public boolean greaterThan(Range other) {
        return this.from > other.to;
    }

    public boolean lessThan(Range other) {
        return this.to < other.from;
    }

    /**
     * Determines whether the range contains the given range, i.e. all numbers in the other range are also present
     * in this range.
     * @param other
     * @return  true when this range contains the other.
     */
    public boolean contains(Range other) {
        return this.from <= other.from && this.to >= other.to;
    }

    /**
     * Returns true when this range contains the given range, but the range bounds (from and to) neither do match.
     * @param other
     * @return
     */
    public boolean properlyContains(Range other) {
        return this.from < other.from && this.to > other.to;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Range)) return false;
        Range range = (Range) o;
        return Objects.equals(from, range.from) && Objects.equals(to, range.to);
    }

    @Override
    public int hashCode() {
        return Objects.hash(from, to);
    }

    @Override
    public String toString() {
        return "[" + to + ".." + from + "]";
    }

    public int size() {
        return (int) (to - from + 1);
    }

    public long getLargest() {
        return to;
    }

    public long getSmallest() {
        return from;
    }

    public Stream<Long> stream() {
        return Stream.generate(new StreamElementGenerator()).limit(size());
    }

    private class StreamElementGenerator implements Supplier<Long> {

        private long next = to;

        @Override
        public Long get() {
            return next--;
        }
    }
}
