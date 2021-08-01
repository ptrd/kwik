package net.luminis.quic.ack;

import java.util.Iterator;
import java.util.List;
import java.util.Objects;

/**
 * Immutable range, identified by a "from" and a "to" field, both are inclusive (part of the range).
 */
public class Range {

    private final Long from;
    private final Long to;

    public Range(Long from, Long to) {
        if (from > to) {
            throw new IllegalArgumentException();
        }
        this.from = from;
        this.to = to;
    }

    public Range(Long fromTo) {
        this.from = fromTo;
        this.to = fromTo;
    }

    public boolean canBeExtendedWith(Long number) {
        return number == from - 1 || number == to + 1;
    }

    public boolean contains(Long number) {
        return number >= from && number <= to;
    }

    public Range extendWith(Long number) {
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

    public Range extendWith(Long number, Range next) {
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

    /**
     * Invariant (pre- and post-condition): list is sorted from largest range to smallest and ranges do not overlap.
     * @param ranges
     * @param number
     * @return  true is the range list is changed, i.e. when a range is extended or a new range is added.
     */
    public static boolean extendRangeList(List<Range> ranges, Long number) {
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
}
