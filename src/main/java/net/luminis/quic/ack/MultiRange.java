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

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;

/**
 * A list of ranges.
 */
public class MultiRange {

    private final List<Range> ranges;

    public MultiRange(Range range1, Range range2) {
        ranges = List.of(range1, range2);
    }

    public MultiRange(Range range) {
        ranges = List.of(range);
    }

    public MultiRange(long from, long to) {
        ranges = List.of(new Range(from, to));
    }

    private MultiRange() {
        ranges = emptyList();
    }

    public static MultiRange empty() {
        return new MultiRange();
    }

    public List<Range> ranges() {
        return ranges;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MultiRange)) return false;

        MultiRange that = (MultiRange) o;

        return ranges != null ? ranges.equals(that.ranges) : that.ranges == null;
    }

    @Override
    public int hashCode() {
        return ranges != null ? ranges.hashCode() : 0;
    }

    @Override
    public String toString() {
        return ranges.toString();
    }

    public Stream<Long> stream() {
        int size = ranges.stream().mapToInt(r -> r.size()).sum();
        return Stream.generate(new StreamElementGenerator()).limit(size);
    }

    private class StreamElementGenerator implements Supplier<Long> {
        private int currentRange = ranges.size() - 1;
        private long next = currentRange >= 0? ranges.get(currentRange).getLargest(): -1;

        @Override
        public Long get() {
            long current = next;
            if (current > ranges.get(currentRange).getSmallest()) {
                next = current - 1;
            }
            else {
                currentRange--;
                next = currentRange >= 0? ranges.get(currentRange).getLargest(): -1;
            }
            return current;
        }
    }
}
